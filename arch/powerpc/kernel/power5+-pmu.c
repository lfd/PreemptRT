/*
 * Performance counter support for POWER5 (not POWER5++) processors.
 *
 * Copyright 2009 Paul Mackerras, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/perf_counter.h>
#include <asm/reg.h>

/*
 * Bits in event code for POWER5+ (POWER5 GS) and POWER5++ (POWER5 GS DD3)
 */
#define PM_PMC_SH	20	/* PMC number (1-based) for direct events */
#define PM_PMC_MSK	0xf
#define PM_PMC_MSKS	(PM_PMC_MSK << PM_PMC_SH)
#define PM_UNIT_SH	16	/* TTMMUX number and setting - unit select */
#define PM_UNIT_MSK	0xf
#define PM_BYTE_SH	12	/* Byte number of event bus to use */
#define PM_BYTE_MSK	7
#define PM_GRS_SH	8	/* Storage subsystem mux select */
#define PM_GRS_MSK	7
#define PM_BUSEVENT_MSK	0x80	/* Set if event uses event bus */
#define PM_PMCSEL_MSK	0x7f

/* Values in PM_UNIT field */
#define PM_FPU		0
#define PM_ISU0		1
#define PM_IFU		2
#define PM_ISU1		3
#define PM_IDU		4
#define PM_ISU0_ALT	6
#define PM_GRS		7
#define PM_LSU0		8
#define PM_LSU1		0xc
#define PM_LASTUNIT	0xc

/*
 * Bits in MMCR1 for POWER5+
 */
#define MMCR1_TTM0SEL_SH	62
#define MMCR1_TTM1SEL_SH	60
#define MMCR1_TTM2SEL_SH	58
#define MMCR1_TTM3SEL_SH	56
#define MMCR1_TTMSEL_MSK	3
#define MMCR1_TD_CP_DBG0SEL_SH	54
#define MMCR1_TD_CP_DBG1SEL_SH	52
#define MMCR1_TD_CP_DBG2SEL_SH	50
#define MMCR1_TD_CP_DBG3SEL_SH	48
#define MMCR1_GRS_L2SEL_SH	46
#define MMCR1_GRS_L2SEL_MSK	3
#define MMCR1_GRS_L3SEL_SH	44
#define MMCR1_GRS_L3SEL_MSK	3
#define MMCR1_GRS_MCSEL_SH	41
#define MMCR1_GRS_MCSEL_MSK	7
#define MMCR1_GRS_FABSEL_SH	39
#define MMCR1_GRS_FABSEL_MSK	3
#define MMCR1_PMC1_ADDER_SEL_SH	35
#define MMCR1_PMC2_ADDER_SEL_SH	34
#define MMCR1_PMC3_ADDER_SEL_SH	33
#define MMCR1_PMC4_ADDER_SEL_SH	32
#define MMCR1_PMC1SEL_SH	25
#define MMCR1_PMC2SEL_SH	17
#define MMCR1_PMC3SEL_SH	9
#define MMCR1_PMC4SEL_SH	1
#define MMCR1_PMCSEL_SH(n)	(MMCR1_PMC1SEL_SH - (n) * 8)
#define MMCR1_PMCSEL_MSK	0x7f

/*
 * Bits in MMCRA
 */

/*
 * Layout of constraint bits:
 * 6666555555555544444444443333333333222222222211111111110000000000
 * 3210987654321098765432109876543210987654321098765432109876543210
 *             [  ><><>< ><> <><>[  >      <  ><  ><  ><  ><><><><>
 *             NC  G0G1G2 G3 T0T1 UC        B0  B1  B2  B3 P4P3P2P1
 *
 * NC - number of counters
 *     51: NC error 0x0008_0000_0000_0000
 *     48-50: number of events needing PMC1-4 0x0007_0000_0000_0000
 *
 * G0..G3 - GRS mux constraints
 *     46-47: GRS_L2SEL value
 *     44-45: GRS_L3SEL value
 *     41-44: GRS_MCSEL value
 *     39-40: GRS_FABSEL value
 *	Note that these match up with their bit positions in MMCR1
 *
 * T0 - TTM0 constraint
 *     36-37: TTM0SEL value (0=FPU, 2=IFU, 3=ISU1) 0x30_0000_0000
 *
 * T1 - TTM1 constraint
 *     34-35: TTM1SEL value (0=IDU, 3=GRS) 0x0c_0000_0000
 *
 * UC - unit constraint: can't have all three of FPU|IFU|ISU1, ISU0, IDU|GRS
 *     33: UC3 error 0x02_0000_0000
 *     32: FPU|IFU|ISU1 events needed 0x01_0000_0000
 *     31: ISU0 events needed 0x01_8000_0000
 *     30: IDU|GRS events needed 0x00_4000_0000
 *
 * B0
 *     20-23: Byte 0 event source 0x00f0_0000
 *	      Encoding as for the event code
 *
 * B1, B2, B3
 *     16-19, 12-15, 8-11: Byte 1, 2, 3 event sources
 *
 * P4
 *     7: P1 error 0x80
 *     6-7: Count of events needing PMC4
 *
 * P1..P3
 *     0-6: Count of events needing PMC1..PMC3
 */

static const int grsel_shift[8] = {
	MMCR1_GRS_L2SEL_SH, MMCR1_GRS_L2SEL_SH, MMCR1_GRS_L2SEL_SH,
	MMCR1_GRS_L3SEL_SH, MMCR1_GRS_L3SEL_SH, MMCR1_GRS_L3SEL_SH,
	MMCR1_GRS_MCSEL_SH, MMCR1_GRS_FABSEL_SH
};

/* Masks and values for using events from the various units */
static u64 unit_cons[PM_LASTUNIT+1][2] = {
	[PM_FPU] =   { 0x3200000000ull, 0x0100000000ull },
	[PM_ISU0] =  { 0x0200000000ull, 0x0080000000ull },
	[PM_ISU1] =  { 0x3200000000ull, 0x3100000000ull },
	[PM_IFU] =   { 0x3200000000ull, 0x2100000000ull },
	[PM_IDU] =   { 0x0e00000000ull, 0x0040000000ull },
	[PM_GRS] =   { 0x0e00000000ull, 0x0c40000000ull },
};

static int power5p_get_constraint(unsigned int event, u64 *maskp, u64 *valp)
{
	int pmc, byte, unit, sh;
	int bit, fmask;
	u64 mask = 0, value = 0;

	pmc = (event >> PM_PMC_SH) & PM_PMC_MSK;
	if (pmc) {
		if (pmc > 4)
			return -1;
		sh = (pmc - 1) * 2;
		mask |= 2 << sh;
		value |= 1 << sh;
	}
	if (event & PM_BUSEVENT_MSK) {
		unit = (event >> PM_UNIT_SH) & PM_UNIT_MSK;
		if (unit > PM_LASTUNIT)
			return -1;
		if (unit == PM_ISU0_ALT)
			unit = PM_ISU0;
		mask |= unit_cons[unit][0];
		value |= unit_cons[unit][1];
		byte = (event >> PM_BYTE_SH) & PM_BYTE_MSK;
		if (byte >= 4) {
			if (unit != PM_LSU1)
				return -1;
			/* Map LSU1 low word (bytes 4-7) to unit LSU1+1 */
			++unit;
			byte &= 3;
		}
		if (unit == PM_GRS) {
			bit = event & 7;
			fmask = (bit == 6)? 7: 3;
			sh = grsel_shift[bit];
			mask |= (u64)fmask << sh;
			value |= (u64)((event >> PM_GRS_SH) & fmask) << sh;
		}
		/* Set byte lane select field */
		mask  |= 0xfULL << (20 - 4 * byte);
		value |= (u64)unit << (20 - 4 * byte);
	}
	mask  |= 0x8000000000000ull;
	value |= 0x1000000000000ull;
	*maskp = mask;
	*valp = value;
	return 0;
}

#define MAX_ALT	3	/* at most 3 alternatives for any event */

static const unsigned int event_alternatives[][MAX_ALT] = {
	{ 0x100c0,  0x40001f },			/* PM_GCT_FULL_CYC */
	{ 0x120e4,  0x400002 },			/* PM_GRP_DISP_REJECT */
	{ 0x230e2,  0x323087 },			/* PM_BR_PRED_CR */
	{ 0x230e3,  0x223087, 0x3230a0 },	/* PM_BR_PRED_TA */
	{ 0x410c7,  0x441084 },			/* PM_THRD_L2MISS_BOTH_CYC */
	{ 0x800c4,  0xc20e0 },			/* PM_DTLB_MISS */
	{ 0xc50c6,  0xc60e0 },			/* PM_MRK_DTLB_MISS */
	{ 0x100009, 0x200009 },			/* PM_INST_CMPL */
	{ 0x200015, 0x300015 },			/* PM_LSU_LMQ_SRQ_EMPTY_CYC */
	{ 0x300009, 0x400009 },			/* PM_INST_DISP */
};

/*
 * Scan the alternatives table for a match and return the
 * index into the alternatives table if found, else -1.
 */
static int find_alternative(unsigned int event)
{
	int i, j;

	for (i = 0; i < ARRAY_SIZE(event_alternatives); ++i) {
		if (event < event_alternatives[i][0])
			break;
		for (j = 0; j < MAX_ALT && event_alternatives[i][j]; ++j)
			if (event == event_alternatives[i][j])
				return i;
	}
	return -1;
}

static const unsigned char bytedecode_alternatives[4][4] = {
	/* PMC 1 */	{ 0x21, 0x23, 0x25, 0x27 },
	/* PMC 2 */	{ 0x07, 0x17, 0x0e, 0x1e },
	/* PMC 3 */	{ 0x20, 0x22, 0x24, 0x26 },
	/* PMC 4 */	{ 0x07, 0x17, 0x0e, 0x1e }
};

/*
 * Some direct events for decodes of event bus byte 3 have alternative
 * PMCSEL values on other counters.  This returns the alternative
 * event code for those that do, or -1 otherwise.  This also handles
 * alternative PCMSEL values for add events.
 */
static int find_alternative_bdecode(unsigned int event)
{
	int pmc, altpmc, pp, j;

	pmc = (event >> PM_PMC_SH) & PM_PMC_MSK;
	if (pmc == 0 || pmc > 4)
		return -1;
	altpmc = 5 - pmc;	/* 1 <-> 4, 2 <-> 3 */
	pp = event & PM_PMCSEL_MSK;
	for (j = 0; j < 4; ++j) {
		if (bytedecode_alternatives[pmc - 1][j] == pp) {
			return (event & ~(PM_PMC_MSKS | PM_PMCSEL_MSK)) |
				(altpmc << PM_PMC_SH) |
				bytedecode_alternatives[altpmc - 1][j];
		}
	}

	/* new decode alternatives for power5+ */
	if (pmc == 1 && (pp == 0x0d || pp == 0x0e))
		return event + (2 << PM_PMC_SH) + (0x2e - 0x0d);
	if (pmc == 3 && (pp == 0x2e || pp == 0x2f))
		return event - (2 << PM_PMC_SH) - (0x2e - 0x0d);

	/* alternative add event encodings */
	if (pp == 0x10 || pp == 0x28)
		return ((event ^ (0x10 ^ 0x28)) & ~PM_PMC_MSKS) |
			(altpmc << PM_PMC_SH);

	return -1;
}

static int power5p_get_alternatives(unsigned int event, unsigned int alt[])
{
	int i, j, ae, nalt = 1;

	alt[0] = event;
	nalt = 1;
	i = find_alternative(event);
	if (i >= 0) {
		for (j = 0; j < MAX_ALT; ++j) {
			ae = event_alternatives[i][j];
			if (ae && ae != event)
				alt[nalt++] = ae;
		}
	} else {
		ae = find_alternative_bdecode(event);
		if (ae > 0)
			alt[nalt++] = ae;
	}
	return nalt;
}

static int power5p_compute_mmcr(unsigned int event[], int n_ev,
				unsigned int hwc[], u64 mmcr[])
{
	u64 mmcr1 = 0;
	unsigned int pmc, unit, byte, psel;
	unsigned int ttm;
	int i, isbus, bit, grsel;
	unsigned int pmc_inuse = 0;
	unsigned char busbyte[4];
	unsigned char unituse[16];
	int ttmuse;

	if (n_ev > 4)
		return -1;

	/* First pass to count resource use */
	memset(busbyte, 0, sizeof(busbyte));
	memset(unituse, 0, sizeof(unituse));
	for (i = 0; i < n_ev; ++i) {
		pmc = (event[i] >> PM_PMC_SH) & PM_PMC_MSK;
		if (pmc) {
			if (pmc > 4)
				return -1;
			if (pmc_inuse & (1 << (pmc - 1)))
				return -1;
			pmc_inuse |= 1 << (pmc - 1);
		}
		if (event[i] & PM_BUSEVENT_MSK) {
			unit = (event[i] >> PM_UNIT_SH) & PM_UNIT_MSK;
			byte = (event[i] >> PM_BYTE_SH) & PM_BYTE_MSK;
			if (unit > PM_LASTUNIT)
				return -1;
			if (unit == PM_ISU0_ALT)
				unit = PM_ISU0;
			if (byte >= 4) {
				if (unit != PM_LSU1)
					return -1;
				++unit;
				byte &= 3;
			}
			if (busbyte[byte] && busbyte[byte] != unit)
				return -1;
			busbyte[byte] = unit;
			unituse[unit] = 1;
		}
	}

	/*
	 * Assign resources and set multiplexer selects.
	 *
	 * PM_ISU0 can go either on TTM0 or TTM1, but that's the only
	 * choice we have to deal with.
	 */
	if (unituse[PM_ISU0] &
	    (unituse[PM_FPU] | unituse[PM_IFU] | unituse[PM_ISU1])) {
		unituse[PM_ISU0_ALT] = 1;	/* move ISU to TTM1 */
		unituse[PM_ISU0] = 0;
	}
	/* Set TTM[01]SEL fields. */
	ttmuse = 0;
	for (i = PM_FPU; i <= PM_ISU1; ++i) {
		if (!unituse[i])
			continue;
		if (ttmuse++)
			return -1;
		mmcr1 |= (u64)i << MMCR1_TTM0SEL_SH;
	}
	ttmuse = 0;
	for (; i <= PM_GRS; ++i) {
		if (!unituse[i])
			continue;
		if (ttmuse++)
			return -1;
		mmcr1 |= (u64)(i & 3) << MMCR1_TTM1SEL_SH;
	}
	if (ttmuse > 1)
		return -1;

	/* Set byte lane select fields, TTM[23]SEL and GRS_*SEL. */
	for (byte = 0; byte < 4; ++byte) {
		unit = busbyte[byte];
		if (!unit)
			continue;
		if (unit == PM_ISU0 && unituse[PM_ISU0_ALT]) {
			/* get ISU0 through TTM1 rather than TTM0 */
			unit = PM_ISU0_ALT;
		} else if (unit == PM_LSU1 + 1) {
			/* select lower word of LSU1 for this byte */
			mmcr1 |= 1ull << (MMCR1_TTM3SEL_SH + 3 - byte);
		}
		ttm = unit >> 2;
		mmcr1 |= (u64)ttm << (MMCR1_TD_CP_DBG0SEL_SH - 2 * byte);
	}

	/* Second pass: assign PMCs, set PMCxSEL and PMCx_ADDER_SEL fields */
	for (i = 0; i < n_ev; ++i) {
		pmc = (event[i] >> PM_PMC_SH) & PM_PMC_MSK;
		unit = (event[i] >> PM_UNIT_SH) & PM_UNIT_MSK;
		byte = (event[i] >> PM_BYTE_SH) & PM_BYTE_MSK;
		psel = event[i] & PM_PMCSEL_MSK;
		isbus = event[i] & PM_BUSEVENT_MSK;
		if (!pmc) {
			/* Bus event or any-PMC direct event */
			for (pmc = 0; pmc < 4; ++pmc) {
				if (!(pmc_inuse & (1 << pmc)))
					break;
			}
			if (pmc >= 4)
				return -1;
			pmc_inuse |= 1 << pmc;
		} else {
			/* Direct event */
			--pmc;
			if (isbus && (byte & 2) &&
			    (psel == 8 || psel == 0x10 || psel == 0x28))
				/* add events on higher-numbered bus */
				mmcr1 |= 1ull << (MMCR1_PMC1_ADDER_SEL_SH - pmc);
		}
		if (isbus && unit == PM_GRS) {
			bit = psel & 7;
			grsel = (event[i] >> PM_GRS_SH) & PM_GRS_MSK;
			mmcr1 |= (u64)grsel << grsel_shift[bit];
		}
		if ((psel & 0x58) == 0x40 && (byte & 1) != ((pmc >> 1) & 1))
			/* select alternate byte lane */
			psel |= 0x10;
		if (pmc <= 3)
			mmcr1 |= psel << MMCR1_PMCSEL_SH(pmc);
		hwc[i] = pmc;
	}

	/* Return MMCRx values */
	mmcr[0] = 0;
	if (pmc_inuse & 1)
		mmcr[0] = MMCR0_PMC1CE;
	if (pmc_inuse & 0x3e)
		mmcr[0] |= MMCR0_PMCjCE;
	mmcr[1] = mmcr1;
	mmcr[2] = 0;
	return 0;
}

static void power5p_disable_pmc(unsigned int pmc, u64 mmcr[])
{
	if (pmc <= 3)
		mmcr[1] &= ~(0x7fUL << MMCR1_PMCSEL_SH(pmc));
}

static int power5p_generic_events[] = {
	[PERF_COUNT_CPU_CYCLES] = 0xf,
	[PERF_COUNT_INSTRUCTIONS] = 0x100009,
	[PERF_COUNT_CACHE_REFERENCES] = 0x1c10a8,	/* LD_REF_L1 */
	[PERF_COUNT_CACHE_MISSES] = 0x3c1088,		/* LD_MISS_L1 */
	[PERF_COUNT_BRANCH_INSTRUCTIONS] = 0x230e4,	/* BR_ISSUED */ 
	[PERF_COUNT_BRANCH_MISSES] = 0x230e5,		/* BR_MPRED_CR */
};

struct power_pmu power5p_pmu = {
	.n_counter = 4,
	.max_alternatives = MAX_ALT,
	.add_fields = 0x7000000000055ull,
	.test_adder = 0x3000040000000ull,
	.compute_mmcr = power5p_compute_mmcr,
	.get_constraint = power5p_get_constraint,
	.get_alternatives = power5p_get_alternatives,
	.disable_pmc = power5p_disable_pmc,
	.n_generic = ARRAY_SIZE(power5p_generic_events),
	.generic_events = power5p_generic_events,
};
