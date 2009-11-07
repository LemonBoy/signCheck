#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h> 
#include <gccore.h>
#include <fat.h>
#include <sdcard/wiisd_io.h>
#include <wiiuse/wpad.h>

#include "ticket_dat.h"
#include "tmd_dat.h"

/* #define SignCheck_Version "0.1 aka IceCream build" */
/* #define SignCheck_Version "0.2 aka nintenDO IT! build" */
/* #define SignCheck_Version "0.3 aka /dev/nintystuff build" */
#define SignCheck_Version "0.3b aka loveSexWii build" 

#define roundTo32(x)  			(-(-(x) & -(32)))
#define makeTitleId(x,y)		(((u64)(x) << 32) | (y))

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

FILE * logFile;
int iosTable[256];
s32 region;

static u8 certs_sys[0xA00] ATTRIBUTE_ALIGN(32);

int initVideo()
{
	VIDEO_Init();
	rmode = VIDEO_GetPreferredMode(NULL);
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	CON_Init(xfb, 60, 60, rmode->fbWidth, rmode->xfbHeight, rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();

	printf("\x1b[2;0H");
	
	return 1;
}

/* System checks. */

int CheckUsb2Module()
{
	int ret = IOS_Open("/dev/usb/ehc", 1);
	if (ret < 0) 
		return 0;
	IOS_Close(ret);
	return 1;
}
	

int CheckFlashAccess()
{
	int ret = IOS_Open("/dev/flash", 1);
	if (ret < 0)
	{
		return 0;
	}
	IOS_Close(ret);
	return 1;
}

int CheckBoot2Access()
{
	int ret = IOS_Open("/dev/boot2", 1);
	if (ret < 0)
	{
		return 0;
	}
	IOS_Close(ret);
	return 1;
}

int CheckEsIdentify()
{
	int ret = -1;
	u32 keyid;
	
	ret = ES_Identify((signed_blob*)certs_sys, sizeof(certs_sys), (signed_blob*)tmd_dat, tmd_dat_size, (signed_blob*)ticket_dat, ticket_dat_size, &keyid);

	if (ret < 0)
	{
		return 0;
	}
	return 1;
}	

/* Misc stuff. */

char* CheckRegion()
{	
	region = CONF_GetRegion();
	
	switch (region)
	{
		case CONF_REGION_JP:
			return "Japan";
		case CONF_REGION_EU:
			return "Europe";
		case CONF_REGION_US:
			return "Usa";
		case CONF_REGION_KR:
			return "Korea";
		default:
			return "Unknown?";
	}
}

int sortCallback(const void * first, const void * second)
{
  return ( *(u32*)first - *(u32*)second );
}

/* Deep stuff :D */

int GetCert()
{
	u32 fd;
	
	fd = IOS_Open("/sys/cert.sys", 1);
	if (IOS_Read(fd, certs_sys, sizeof(certs_sys)) < sizeof(certs_sys))
		return -1;
	IOS_Close(fd);
	return 0;
}

int ScanIos()
{
	int i, ret;
	u32 titlesCount, tmdSize, iosFound;
	static u64 *titles;
	
	ES_GetNumTitles(&titlesCount);
	titles = memalign(32, titlesCount * sizeof(u64));
	ES_GetTitles(titles, titlesCount);

	iosFound = 0;
	
	for (i = 0; i < titlesCount; i++)
	{
		ret = ES_GetStoredTMDSize(titles[i], &tmdSize);
		if (ret < 0)
			continue;
		static u8 tmdBuffer[MAX_SIGNED_TMD_SIZE] ATTRIBUTE_ALIGN(32);
		signed_blob *s_tmd = (signed_blob *)tmdBuffer;
		ES_GetStoredTMD(titles[i], s_tmd, tmdSize);
		if (ret < 0)
			continue;
		
		tmd *title_tmd = (tmd *)SIGNATURE_PAYLOAD(s_tmd);
		
		if (((title_tmd->title_id >> 32) == 1) && ((title_tmd->title_id & 0xFFFFFFFF) != 2) && \
			((title_tmd->title_id & 0xFFFFFFFF) != 0x100) && ((title_tmd->title_id & 0xFFFFFFFF) != 0x101) && \
			(title_tmd->num_contents != 1) && (title_tmd->num_contents != 3))
		{
			iosTable[iosFound] = titles[i] & 0xFFFFFFFF;
			iosFound++;
		}
	}
	
	qsort (iosTable, iosFound, sizeof(u32), sortCallback);
	
	return iosFound;
}

/* Logging stuff. */

char logBuffer[1024*1024];

int writebackLog()
{
	logFile = fopen("sd:/signCheck.csv", "wb");

	fwrite(logBuffer, 1, strlen(logBuffer), logFile);
	fclose(logFile);
	
	return 0;
}

void addLogHeaders()
{
	char tmp[1024];
	u32 deviceId;
	
	ES_GetDeviceID(&deviceId);
		
	sprintf(tmp, "\"SignCheck %s report\"\n", SignCheck_Version);
	strcat(logBuffer, tmp);
	sprintf(tmp, "\"Wii region\", %s\n", CheckRegion());
	strcat(logBuffer, tmp);
	sprintf(tmp, "\"Wii unique device id\", %u\n", deviceId);
	strcat(logBuffer, tmp);
	sprintf(tmp, "\n");
	strcat(logBuffer, tmp);
	sprintf(tmp, "%s, %s, %s, %s, %s\n", "\"IOS number\"", "\"Trucha bug\"", "\"Flash access\"", "\"Boot2 access\"", "\"Usb2.0 IOS tree\"");
	strcat(logBuffer, tmp);
	sprintf(tmp, "\n");
	strcat(logBuffer, tmp);
}

void addLogEntry(int iosNumber, int iosVersion, int trucha, int flash, int boot2, int usb2)
{
	char tmp[1024];
	sprintf(tmp, "\"IOS%i (ver %i)\", %s, %s, %s, %s\n", iosNumber, iosVersion, ((trucha) ? "Enabled" : "Disabled"), \
		((flash) ? "Enabled" : "Disabled"), ((boot2) ? "Enabled" : "Disabled"), ((usb2) ? "Enabled" : "Disabled"));
	
	strcat(logBuffer, tmp);
}


int main(int argc, char **argv) 
{	
	int iosToTest = 0;
	int reportResults[4];
	
	initVideo();

	printf("\t[*] \x1b[33;1mSignCheck\x1b[37;1m %s by The Lemon Man\n", SignCheck_Version);
	printf("\n");
	printf("\t[*] Using ios %i (rev %i)\n\t[*] Region %s\n\t[*] Hollywood version 0x%x\n", IOS_GetVersion(), IOS_GetRevision(), CheckRegion(), *(u32 *)0x80003138);
	printf("\t[*] Getting certs.sys from the NAND\t\t\t\t");
	printf("%s\n", (!GetCert()) ? "[DONE]" : "[FAIL]");
	printf("\n");
	iosToTest = ScanIos() - 1;
	printf("\t[*] Found %i ios on this console.\n", iosToTest);
	printf("\n");
	
	addLogHeaders();

	while (iosToTest > 0)
	{		
		printf("\x1b[11;0H");
		fflush(stdout);
		
		IOS_ReloadIOS(iosTable[iosToTest]);

		printf("\t[*] Analyzed IOS%d(rev %d)...\n", iosTable[iosToTest], IOS_GetRevision());

		printf("\t\tTrucha bug           : %sabled \n", (reportResults[1] = CheckEsIdentify())     ? "En" : "Dis");
		printf("\t\tFlash access         : %sabled \n", (reportResults[2] = CheckFlashAccess())    ? "En" : "Dis");
		printf("\t\tBoot2 access         : %sabled \n", (reportResults[3] = CheckBoot2Access())    ? "En" : "Dis");
		printf("\t\tUsb 2.0 IOS tree     : %sabled \n", (reportResults[4] = CheckUsb2Module())     ? "En" : "Dis");
		
		addLogEntry(iosTable[iosToTest], IOS_GetRevision(), reportResults[1], reportResults[2], reportResults[3], reportResults[4]);
		
		printf("\t[*] Press the reset button to continue...\n");
		
		while (!SYS_ResetButtonDown());

		iosToTest--;
	}
	
	IOS_ReloadIOS(36);
	
	printf("\n");
	
	if(fatInitDefault())
	{
		printf("\t[*] Creating the log (signCheck.csv)...");
		writebackLog();
	} else {
		printf("\t[*] Cannot create the log...");
	}

	printf("\n\t[*] All done, you can find the report into the sd root");
	printf("\n\t[*] Press reset to return to the wii menu");
	
	while (!SYS_ResetButtonDown());
		
	SYS_ResetSystem(SYS_RETURNTOMENU, 0, 0);
	
	return 0;
}
