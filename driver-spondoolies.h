
#ifndef SPONDA_HFILE
#define SPONDA_HFILE


#include "miner.h"
#include "mg_proto_parser.h"


#define MAX_SPOND_JOBS 10

typedef enum adapter_state {
  ADAPTER_STATE_INIT,
  ADAPTER_STATE_OPERATIONAL,
} ADAPTER_STATE; 



typedef enum spond_work_state {
  SPONDWORK_STATE_EMPTY,
    SPONDWORK_STATE_IN_BUSY,
//    SPONDWORK_STATE_COMPLETE,
} SPONDWORK_STATE; 

#define MAX_JOBS_IN_MINERGATE MINERGATE_TOTAL_QUEUE // 1.5 sec worth of jobs

typedef struct {
    struct work      *cgminer_work;
    SPONDWORK_STATE  state;
    uint32_t         merkel_root;
    time_t           start_time;
    int              job_id;
} spond_driver_work;

struct spond_adapter {
  pthread_mutex_t lock;
  // Lock the job queue
  /*
  pthread_mutex_t qlock;
  pthread_cond_t qcond;
*/
  ADAPTER_STATE adapter_state;
  void* cgpu;
  
  // Statistics
  int wins;
  int good;
  int empty;
  int bad;
  int overflow;
  // state 
  int works_in_driver;
  int works_in_minergate;
  int works_pending_tx;
    

    int socket_fd;

  
  int current_job_id; // 0 to 1000
  int parse_resp;
    minergate_req_packet* mp_next_req;
    minergate_rsp_packet* mp_last_rsp;
    spond_driver_work my_jobs[MAX_JOBS_IN_MINERGATE]; 
};


// returns non-zero if needs to change ASICs.
int spond_one_sec_timer_scaling(struct spond_adapter *a, int t);
int spond_do_scaling(struct spond_adapter *a);

extern void one_sec_spondoolies_watchdog(int uptime);

#define REQUEST_PERIOD (150000)  //  times per second - in usec
#define REQUEST_SIZE   200      //  jobs per request



#endif

