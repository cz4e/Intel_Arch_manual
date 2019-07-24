#ifndef	_PAGING_CPUID_
#define _PAGING_CPUID_
#endif	

#include <stdio.h>

#define EDX_PSE_SHIFT		3		/* page size extension, support for 4-MByte page 		*/
#define EDX_PAE_SHIFT		6		/* physical-address extension			 		*/
#define EDX_PGE_SHIFT		13		/* global-page support						*/
#define	EDX_PAT_SHIFT		16		/* page-attribute table						*/
#define EDX_PSE_36_SHIFT	17		/* page-size extensions with 40-bit physcial address extension 	*/
#define EDX_NX_SHIFT		20		/* execute disable						*/
#define	EDX_PAGE1GB_SHIFT	26		/* 1-GByte support						*/
#define	EDX_LM_SHIFT		29		/* IA-32e mode support						*/

#define ECX_PCID_SHIFT		17		/* process-context identifiers					*/
#define	ECX_PKU_SHIFT		3		/* protection keys						*/


#define	EBX_SMEP_SHIFT		7		/* supervisor-mode execution prevention				*/
#define	EBX_SMAP_SHIFT		20		/* supervisor-mode access prevention				*/


#define EAX_MAXPHYADDR_MASK	0x00ff		/* MAXPHYADDR							*/
#define EAX_LINEAR_ADDR_MASK	0xff00		/* Linear address width						*/


int 
cpuid_01H_get_edx(void)
{
	int _edx;
	__asm__ volatile(
			"movl	$0x01,%%eax\n\t"
			"cpuid\n\t"
			"movl	%%edx,%0\n\t"
			:"=d"(_edx)
			);
	return (_edx);
}

int
cpuid_01H_get_ecx(void)
{
	int _ecx;
	__asm__ volatile(
			"movl	$0x01,%%eax\n\t"
			"cpuid\n\t"
			"movl	%%ecx,%0\n\t"
			:"=c"(_ecx)
			);
	return (_ecx);
}

int
cpuid_07H_00H_get_ebx(void)
{
	int _ebx;
	__asm__ volatile(
			"movl	$0x07,%%eax\n\t"
			"movl	$0x00,%%ecx\n\t"
			"cpuid\n\t"
			"movl	%%ebx,%0\n\t"
			:"=b"(_ebx)
			);
	return (_ebx);
}

int
cpuid_07H_00H_get_ecx(void)
{
	int	_ecx;
	__asm__ volatile(
			"movl	$0x07,%%eax\n\t"
			"movl	$0x00,%%ecx\n\t"
			"cpuid\n\t"
			"movl	%%ecx,%0\n\t"
			:"=c"(_ecx)
			);
	return (_ecx);
}

int
cpuid_80000001H_get_edx(void)
{
	int	_edx;
	__asm__ volatile(
			"movl	$0x80000001,%%eax\n\t"
			"cpuid\n\t"
			"movl	%%edx,%0\n\t"
			:"=d"(_edx)
			);
	return (_edx);
}

int
cpuid_80000008H_get_eax(void)
{
	int	_eax;
	__asm__ volatile(
			"movl	$0x80000008,%%eax\n\t"
			"cpuid\n\t"
			"movl	%%eax,%0\n\t"
			:"=a"(_eax)
			);
	return (_eax);
}

#define _true		(_Bool)1
#define _false		(_Bool)0

void
analysis_01H_edx(int _edx)
{
	_Bool PSE = _false,
	      PAE = _false,
	      PGE = _false,
	      PAT = _false,
	      PSE_36 = _false;
	PSE = _edx & (0x1 << EDX_PSE_SHIFT);
	PAE = _edx & (0x1 << EDX_PAE_SHIFT);
	PGE = _edx & (0x1 << EDX_PGE_SHIFT);
	PAT = _edx & (0x1 << EDX_PAT_SHIFT);
	PSE_36 = _edx & (0x1 << EDX_PSE_36_SHIFT);
	
	if(PSE){
		printf("\tPSE: enable\n");
	} else {
		printf("\tPSE: disable\n");
	}

	if(PAE) {
		printf("\tPAE: enable\n");
	} else {
		printf("\tPAE: disable\n");
	}

	if(PGE) {
		printf("\tPGE: enable\n");
	} else {
		printf("\tPGE: disable\n");
	}
	
	if(PAT) {
		printf("\tPAT: The 8-entry page-attribute table is supported\n");
	} else {
		printf("\tPAT: disable\n");
	}

	if(PSE_36) {
		printf("\tPSE-36: Translations using 4-Mbyte pages with 32-paging\n");
	} else {
		printf("\tPSE-36: disable\n");
	}
	return ;
}

void 
analysis_01H_ecx(int _ecx)
{
	_Bool PCID = _ecx & (0x1 << ECX_PCID_SHIFT);
	
	if(PCID) {
		printf("\tPCID: enable\n");
	} else {
		printf("\tPCID: disable\n");
	}
	return ;
}

void
analysis_07H_00H_ebx(int _ebx)
{
	_Bool SMEP = _false,
	      SMAP = _false;
	SMEP = _ebx & (0x1 << EBX_SMEP_SHIFT);
	SMAP = _ebx & (0x1 << EBX_SMAP_SHIFT);
	if(SMEP) {
		printf("\tSMEP: enable superuser-mode executing prevention\n");
	} else {
		printf("\tSMAP: disable\n");
	}
	
	if(SMAP) {
		printf("\tSMAP: enable superuser-mode access prevention\n");
	} else {
		printf("\tSMAP: disable\n");
	}
	return ;
}

void
analysis_07H_00H_ecx(int _ecx)
{
	_Bool PKU = _ecx & (0x1 << ECX_PKU_SHIFT);
	if(PKU) {
		printf("\tPKU: enable protection keys\n");
	} else {
		printf("\tPKU: disable\n");
	}
	return ;
}

void
analysis_80000001H_edx(int _edx)
{
	_Bool NX = _edx & (0x1 << EDX_NX_SHIFT);
	_Bool Page1GB = _edx & (0x1 << EDX_PAGE1GB_SHIFT);
	_Bool LM = _edx & (0x1 << EDX_LM_SHIFT);

	if(NX) {
		printf("\tNX: allow PAE paging and IA-32e paging to disable execute access to sleceted pages\n");
	} else {
		printf("\tNX: disable\n");
	}
	if(Page1GB) {
		printf("\tPage1GB: 1-GByte page support\n");
	} else {
		printf("\tPage1GB: disable\n");
	}

	if(LM) {
		printf("\tLM: enable IA-32e paging\n");
	} else {
		printf("\tLM: disable\n");
	}

	return ;
}

void
analysis_80000008H_eax(int _eax)
{
	char maxphyaddr;
	char linear_address_width;
	
	maxphyaddr = _eax & EAX_MAXPHYADDR_MASK;
	linear_address_width = (_eax & EAX_LINEAR_ADDR_MASK) >> 8;

	printf("\tmax physical address: 0x%x\n",maxphyaddr);
	printf("\tlinear address width: 0x%x\n",linear_address_width);
}

void
show_paging_info(void)
{
	int _01H_edx,
	    _01H_ecx,
	    _07H_00H_ebx,
	    _07H_00H_ecx,
	    _80000001H_edx,
	    _80000008H_eax;

	_01H_edx = cpuid_01H_get_edx();
	_01H_ecx = cpuid_01H_get_ecx();
	_07H_00H_ebx = cpuid_07H_00H_get_ebx();
	_07H_00H_ecx = cpuid_07H_00H_get_ecx();
	_80000001H_edx = cpuid_80000001H_get_edx();
	_80000008H_eax = cpuid_80000008H_get_eax();

	printf("CPU paging information:\n");

	analysis_01H_edx(_01H_edx);
	analysis_01H_ecx(_01H_ecx);
	analysis_07H_00H_ebx(_07H_00H_ebx);
	analysis_07H_00H_ecx(_07H_00H_ecx);
	analysis_80000001H_edx(_80000001H_edx);
	analysis_80000008H_eax(_80000008H_eax);
	
	return ;
}
