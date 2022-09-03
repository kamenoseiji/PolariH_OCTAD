//	VDIF_store.c : Store VDIF data from Octavia and Store to Shared Memory
//
//	Author : Seiji Kameno
//	Created: 2014/08/26
//
#include "shm_VDIF.inc"
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
int VDIFutc();

int main(
	int		argc,			// Number of Arguments
	char	**argv )		// Pointer to Arguments
{
	int		shrd_param_id;				// Shared Memory ID
	struct	SHM_PARAM	*param_ptr;		// Pointer to the Shared Param
	struct	sembuf		sops;			// Semaphore
	int		rv;							// Return Value from K5/VSSP32
	unsigned char	*vdifhead_ptr;		// Pointer to the shared K5 header
	unsigned char	*vdifdata_ptr;		// Pointer to the shared K5 data
	unsigned char	*shm_write_ptr;		// Writing Pointer
	int		sock;						// Socket ID descriptor
	int		frameID=0, prevFrameID=0, threadID=0;		    // Frame ID and thread ID (= stream index)
    int     frame_index;
	struct sockaddr_in	addr;			//  Socket Address
	struct ip_mreq		mreq;			// Multicast Request
	FILE	*dumpfile_ptr;				// Dump File
    int     MaxFrameID;                 // Maximum number of frames in 1 sec
    size_t  PageSize;                   // Bytes per page
    int     pageID, prevPageID;         // Index for page
    int     FramePerPage;               // Frames per page
    long    addr_offset;                // Address from the head of the page
	unsigned char	buf[VDIF_SIZE];		// 1312 bytes
//------------------------------------------ Open Socket to OCTAVIA
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0){
		perror("Socket Failed\n"); printf("%d\n", errno);
		return(-1);
	}
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(60101);
	addr.sin_addr.s_addr    = INADDR_ANY;
	if( bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("Bind Failed\n"); printf("%d\n", errno);
    }
	memset(buf, 0, sizeof(buf));
//------------------------------------------ Access to the SHARED MEMORY
    //-------- SHARED PARAMETERS --------
    if(shm_access(
        SHM_PARAM_KEY,					// ACCESS KEY
        sizeof(struct SHM_PARAM),		// SIZE OF SHM
        &shrd_param_id,					// SHM ID
        &param_ptr) == -1){				// Pointer to the SHM
		perror("  Error : Can't access to the shared memory!!");
		close(sock); return(-1);
	}
	printf("VDIF_store: Succeeded to access the shared parameter [%d]!\n",  param_ptr->shrd_param_id);

    //-------- SHARED VDIF Header and Data to Store --------
	vdifhead_ptr = shmat( param_ptr->shrd_vdifhead_id, NULL, 0 );
	vdifdata_ptr = shmat( param_ptr->shrd_vdifdata_id, NULL, 0 );
	param_ptr->validity |= ENABLE;		// Set Shared memory readiness bit to 1
//------------------------------------------ Read 16 frames to check number of threads (streams)
    frameID = 0; prevFrameID = 0;
    while(frameID >= prevFrameID){
        prevFrameID = frameID;
		rv = recv(sock, buf, sizeof(buf), 0);
		// frameID    = (buf[5] << 16) + (buf[6] << 8) + buf[7];
        memcpy(&frameID, &buf[4], 3);
    }
    MaxFrameID = prevFrameID + 1;
    VDIFutc( buf, param_ptr);
    printf("FrameID=%d prev=%d %02d:%02d:%02d \n", frameID, prevFrameID, param_ptr->hour, param_ptr->min, param_ptr->sec);
    printf("Number of streams: %d\n", NST);
    printf("Max frame ID : %d\n", MaxFrameID);
    PageSize = (param_ptr->fsample / 64)* param_ptr->qbit* NST;    // bytes per page
    printf("Page Size : %ld\n", PageSize);
    FramePerPage = MaxFrameID / 8;
    printf("FramePerPage : %d\n", FramePerPage);
    prevPageID   = (frameID / FramePerPage) & 0x01;
	if(argc > 1){ 	dumpfile_ptr = fopen(argv[1], "w"); }
//------------------------------------------ Paging
	setvbuf(stdout, (char *)NULL, _IONBF, 0); 	// Disable stdout cache
	param_ptr->validity |= ACTIVE;		// Set Sampling Activity Bit to 1
	param_ptr->validity &= (~ENABLE);	// Wait until first second 
//------------------------------------------ Receive VDIF and store into shared memory
 	while( param_ptr->validity & ACTIVE ){
		if( param_ptr->validity & (FINISH + ABSFIN) ){	break; }
		//-------- Read VDIF packet
		rv = recv(sock, buf, sizeof(buf), 0);
        memcpy(&frameID, &buf[4], 3);                       // frameID 200000 frames per sec
        // threadID    = ((buf[11] & 0x03) << 8 ) + buf[10];       
        pageID     = (frameID / FramePerPage) & 0x01;       // PageID = 0 or 1
        addr_offset= pageID* PageSize + (frameID % FramePerPage)* VDIFDATA_SIZE;
		memcpy( &vdifdata_ptr[addr_offset], &buf[VDIFHEAD_SIZE], VDIFDATA_SIZE);
        if(argc > 1){
            fwrite(buf, VDIF_SIZE, 1, dumpfile_ptr);
        }
		//-------- Page refresh?
        if( pageID != prevPageID ){
		    param_ptr->page_index = prevPageID;
            memcpy(vdifhead_ptr, buf, VDIFHEAD_SIZE); // copy VDIF header
            VDIFutc( vdifhead_ptr, param_ptr);
            // printf("%02d:%02d:%02d Page=%d FrameID=%d ThreadID=%d ADDR=%ld\n", param_ptr->hour, param_ptr->min, param_ptr->sec, pageID, frameID, threadID, addr_offset);
	 		param_ptr->validity |= ENABLE;
	 		sops.sem_num = (ushort)SEM_VDIF_PART; sops.sem_op = (short)1; sops.sem_flg = (short)0;
	 		semop(param_ptr->sem_data_id, &sops, 1);
	 		sops.sem_num = (ushort)SEM_VDIF_POWER; sops.sem_op = (short)1; sops.sem_flg = (short)0;
	 		semop(param_ptr->sem_data_id, &sops, 1);
            printf("%04d %03d %02d:%02d:%02d P%d %06d        %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
                param_ptr->year, param_ptr->doy, param_ptr->hour, param_ptr->min, param_ptr->sec, pageID, frameID,
                buf[VDIFHEAD_SIZE + 0], buf[VDIFHEAD_SIZE + 1], buf[VDIFHEAD_SIZE + 2], buf[VDIFHEAD_SIZE + 3],
                buf[VDIFHEAD_SIZE + 4], buf[VDIFHEAD_SIZE + 5], buf[VDIFHEAD_SIZE + 6], buf[VDIFHEAD_SIZE + 7],
                buf[VDIFHEAD_SIZE + 8], buf[VDIFHEAD_SIZE + 9], buf[VDIFHEAD_SIZE +10], buf[VDIFHEAD_SIZE +11],
                buf[VDIFHEAD_SIZE +12], buf[VDIFHEAD_SIZE +13], buf[VDIFHEAD_SIZE +14], buf[VDIFHEAD_SIZE +15]);
            prevPageID = pageID;
        }
	}
//------------------------------------------ Stop Sampling
	fclose(dumpfile_ptr);
	close(sock);
	param_ptr->validity &= (~ACTIVE);		// Set Sampling Activity Bit to 0

    return(0);
}
