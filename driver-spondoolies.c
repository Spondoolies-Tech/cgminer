
#include <float.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include "config.h"

#ifdef WIN32
#include <windows.h>
#endif

#include "compat.h"
#include "miner.h"
#include "mg_proto_parser.h"
#include "driver-spondoolies.h"

extern int opt_g_threads;
struct device_drv spondoolies_drv;


#ifdef WORDS_BIGENDIAN
#  define swap32tobe(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#  define LOCAL_swap32be(type, var, sz)  ;
#  define swap32tole(out, in, sz)  swap32yes(out, in, sz)
#  define LOCAL_swap32le(type, var, sz)  LOCAL_swap32(type, var, sz)
#else
#  define swap32tobe(out, in, sz)  swap32yes(out, in, sz)
#  define LOCAL_swap32be(type, var, sz)  LOCAL_swap32(type, var, sz)
#  define swap32tole(out, in, sz)  ((out == in) ? (void)0 : memmove(out, in, sz))
#  define LOCAL_swap32le(type, var, sz)  ;
#endif
static inline void swap32yes(void*out, const void*in, size_t sz) {
  size_t swapcounter = 0;
  for (swapcounter = 0; swapcounter < sz; ++swapcounter)
    (((uint32_t*)out)[swapcounter]) = swab32(((uint32_t*)in)[swapcounter]);
}


static void print_stats(struct spond_adapter *a) {
  printf("%d wins %d good %d empty %d bad %d overflow %d\n", time(NULL),
    a->wins,
    a->good,
    a->empty,
    a->bad,
    a->overflow);
}


void send_minergate_pkt(const minergate_req_packet* mp_req, 
            minergate_rsp_packet* mp_rsp,
            int  socket_fd) {
  int   nbytes;    
  write(socket_fd, (const void*)mp_req, sizeof(minergate_req_packet));
  nbytes = read(socket_fd, (void*)mp_rsp, sizeof(minergate_rsp_packet));  
  if(nbytes <= 0) {
    _quit(-1);
  }
  //printf("got %d(%d) bytes\n",mp_rsp->data_length, nbytes);
  passert(mp_rsp->magic == 0xcaf4);
}



static bool spondoolies_prepare(struct thr_info *thr)
{
  struct cgpu_info *spondoolies = thr->cgpu;
  assert(spondoolies);
  struct timeval now;

  cgtime(&now);
/* FIXME: Vladik */
#if NEED_FIX
  get_datestamp(spondoolies->init, &now);
#endif
  return true;
}

void spond_print_stats(struct spond_adapter *a) {
  int i;
  printf("---------- ADAPTER STATS ------------\n");
  printf("state %i\n",a->adapter_state);
//  printf("job write %i, read %i, count %i\n",a->job_write_ptr,a->job_read_ptr, a->job_count);
  for (i = 0; i < MAX_SPOND_JOBS; i++) {
    //  printf("  job %i: %p\n", i, a->my_jobs[i]);
  }  
  printf("-------------------------------------\n");

}
 
int init_socket() {
  struct sockaddr_un address;
    int socket_fd;
  socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
   if(socket_fd < 0)
   {
    printf("socket() failed\n");
    perror("Err:");
    return 0;
   }
   
   /* start with a clean address structure */
   memset(&address, 0, sizeof(struct sockaddr_un));
   
   address.sun_family = AF_UNIX;
   sprintf(address.sun_path, MINERGATE_SOCKET_FILE);
   
   if(connect(socket_fd, 
        (struct sockaddr *) &address, 
        sizeof(struct sockaddr_un)) != 0)
   {
    printf("connect() failed\n");
    perror("Err:");
    return 0;
   }

  return socket_fd;
}


static void spondoolies_detect(__maybe_unused bool hotplug)
{
  int success;
  struct spond_adapter *a;
  struct device_drv *drv = &spondoolies_drv;
  applog(LOG_DEBUG, "SPOND spondoolies_detect");
  applog(LOG_DEBUG, "USB scan devices: checking for %s devices", drv->name);
  
#if NEED_FIX
  nDevs = 1;
#endif

  struct cgpu_info *cgpu = calloc(1, sizeof(*cgpu));
  assert(cgpu);
  cgpu->drv = drv;
  cgpu->deven = DEV_ENABLED;
  cgpu->threads = 1;
  cgpu->device_data = calloc(sizeof(struct spond_adapter), 1);
  memset(cgpu->device_data, 0, sizeof(struct spond_adapter));
  if (unlikely(!(cgpu->device_data)))
    quit(1, "Failed to calloc cgpu_info data");
  a = cgpu->device_data;
  a->cgpu = (void*)cgpu;
  a->adapter_state = ADAPTER_STATE_OPERATIONAL;
    a->mp_next_req = allocate_minergate_packet_req(
        0xca, 0xfe);
    a->mp_last_rsp = allocate_minergate_packet_rsp(
        0xca, 0xfe);
     
  pthread_mutex_init(&a->lock, NULL);
  a->socket_fd = init_socket();
  if (a->socket_fd < 1) {
        printf("Error connecting to minergate server!");
    _quit(-1);
  }

  assert(add_cgpu(cgpu));
  applog(LOG_DEBUG, "SPOND spondoolies_detect done");
}


static struct api_data *spondoolies_api_stats(struct cgpu_info *cgpu)
{
  struct api_data *root = NULL;
  applog(LOG_DEBUG, "SPOND spondoolies_api_stats");

  applog(LOG_DEBUG, "SPOND spondoolies_api_stats done");
  return root;
}





unsigned char get_leading_zeroes(const unsigned char *target) {
  unsigned char leading = 0;
  int first_non_zero_chr;
  for (first_non_zero_chr = 31; first_non_zero_chr >= 0;
      first_non_zero_chr--) {
    if (target[first_non_zero_chr] == 0) {
      leading += 8;
    } else { 
      break;
    }
  }

  // j = first non-zero
  uint8_t m = target[first_non_zero_chr];
  while ((m & 0x80) == 0) {
    leading++;
    m = m << 1;
  }
  return leading;
}



static void spondoolies_shutdown(__maybe_unused struct thr_info *thr)
{
}

void fill_minergate_request(minergate_do_job_req* work, struct work *cg_work) {
  static int id = 1;
  id++;
  memset(work, 0, sizeof(minergate_do_job_req));
  //work->
  LOCAL_swap32le(unsigned char, cg_work->midstate, 32/4)
  LOCAL_swap32le(unsigned char, cg_work->data+64, 64/4)
  uint32_t x[64/4];
  swap32yes(x, cg_work->data + 64, 64/4);
  memcpy(work->midstate, cg_work->midstate, 32);
  // TODO - test
  work->mrkle_root = ntohl(x[0]);
  work->timestamp  = ntohl(x[1]);
  work->difficulty = ntohl(x[2]);
  work->leading_zeroes = get_leading_zeroes(cg_work->target);
  work->work_id_in_sw = cg_work->subid;
}


static bool spondoolies_flush_queue(struct cgpu_info *cgpu, struct spond_adapter* a)
{
    if (!a->parse_resp) {
      static int i =0;
      if (i++%10 == 0)
        //print_stats(a);
        // TODO - send packet
        if (a->works_in_minergate + a->works_pending_tx != a->works_in_driver) {
          printf("%d + %d != %d\n",a->works_in_minergate,a->works_pending_tx,a->works_in_driver);
          //print_stats(a);
        }
        assert(a->works_in_minergate + a->works_pending_tx == a->works_in_driver);   
       send_minergate_pkt(a->mp_next_req,  a->mp_last_rsp, a->socket_fd);
       a->mp_next_req->connect = 0;
       a->mp_next_req->req_count = 0;
       a->parse_resp = 1;
       a->works_in_minergate += a->works_pending_tx;
       a->works_pending_tx = 0;
    }
    return true;
}






/* move jobs from  get_queued() to a->my_jobs() */
// returns true if queue full.
struct timeval last_force_queue = {0};   
static bool spondoolies_queue_full(struct cgpu_info *cgpu)
{
    // Only once every 1/10 second do work.
    struct spond_adapter* a = cgpu->device_data;
    int ret = false;
    bool queue_full = false; // queue not full
    mutex_lock(&a->lock);


    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned int usec;
        
    usec=(tv.tv_sec-last_force_queue.tv_sec)*1000000;
    usec+=(tv.tv_usec-last_force_queue.tv_usec);

  // flush queue every REQUEST_PERIOD.
  if (usec >= REQUEST_PERIOD) {
    static int i =0; 
    //if (i++%20 == 0) print_stats(a);
    spondoolies_flush_queue(cgpu, a);
    last_force_queue = tv;
   }

  // see if we have enough jobs
  if (a->works_pending_tx == REQUEST_SIZE) {
    cgsleep_ms(20);
    ret = true;
    goto return_unlock;
  }

  // see if can take 1 more job.
  int next_job_id =  (a->current_job_id+1)%MAX_JOBS_IN_MINERGATE;
    if (a->my_jobs[next_job_id].cgminer_work) {
      cgsleep_ms(40);
      ret = true;
      goto return_unlock;
    }


  struct work *work;
  work = get_queued(cgpu);
  if (!work) {
     ret = true;
     goto return_unlock;
  }
  
  work->thr = cgpu->thr[0];  
  work->thr_id = cgpu->thr[0]->id;
  assert(work->thr);
  a->current_job_id = next_job_id;
  a->works_in_driver++;
  // Get pointer for the request
  minergate_do_job_req* pkt_job =  &a->mp_next_req->req[a->works_pending_tx];

  work->subid = a->current_job_id;
  a->my_jobs[a->current_job_id].cgminer_work = work;
  a->my_jobs[a->current_job_id].state = SPONDWORK_STATE_IN_BUSY;
  fill_minergate_request(pkt_job, work);
  a->mp_next_req->req_count++;
  a->my_jobs[a->current_job_id].merkel_root = pkt_job->mrkle_root;
  a->works_pending_tx++;
   

 return_unlock:
    mutex_unlock(&a->lock);
    return ret;
//}
   
}



// Return completed work to submit_nonce() and work_completed() 
// struct timeval last_force_queue = {0};  
static int64_t spond_scanhash(struct thr_info *thr)
{
    int64_t ghashes = 0;
    struct cgpu_info *cgpu = thr->cgpu;
    struct spond_adapter *a = cgpu->device_data;
    if(a->parse_resp) {
     mutex_lock(&a->lock);
     ghashes+=a->mp_last_rsp->gh_done;
     int array_size = a->mp_last_rsp->rsp_count;
     int i;
     for (i = 0; i < array_size; i++) { // walk the jobs
       minergate_do_job_rsp* work = a->mp_last_rsp->rsp + i;
       int job_id =  work->work_id_in_sw;
        if ((a->my_jobs[job_id].cgminer_work)) {
          if (a->my_jobs[job_id].merkel_root == work->mrkle_root) {
              assert(a->my_jobs[job_id].state == SPONDWORK_STATE_IN_BUSY);
            a->works_in_minergate--;
            a->works_in_driver--;
            if (work->winner_nonce) {
             struct work *cg_work = a->my_jobs[job_id].cgminer_work;
             int r = submit_nonce(cg_work->thr, cg_work, work->winner_nonce);
             //printf("Share status=%d nonce=%x jobid=%x \n", 
             //  r, work->winner_nonce, a->my_jobs[job_id].job_id);
             a->wins++;
            }
            work_completed(a->cgpu, a->my_jobs[job_id].cgminer_work);
            a->good++;              
              a->my_jobs[job_id].cgminer_work = NULL;
              a->my_jobs[job_id].state = SPONDWORK_STATE_EMPTY;  
          } else {
              a->bad++;
              printf("Dropping minergate old job id=%d mrkl=%x my-mrkl=%x\n",job_id,
              a->my_jobs[job_id].merkel_root, 
              work->mrkle_root);  
          }
        } else {
          a->empty++;
          printf("Dropping minergate old job id:%d res:%d!\n",job_id, work->res);
        }
     }
     mutex_unlock(&a->lock);
     a->parse_resp = 0;
    }

        
    //printf("+");


//    minergate_packet* mp_next_req = allocate_minergate_packet(10000, 0xca, 0xfe);

  
  return (ghashes)?ghashes*1000000000+500000000:0;
}

// Drop all current work
void spond_dropwork(struct spond_adapter *a) {
    int job_id;
    printf("---------------------------- DROP WORK!!!!!-----------------\n");
    for (job_id=0; job_id<0x100;job_id++) {
        if ((a->my_jobs[job_id].cgminer_work) ||
           (a->my_jobs[job_id].state == SPONDWORK_STATE_IN_BUSY)) {                
                a->works_in_minergate--;
                a->works_in_driver--;
                work_completed(a->cgpu, a->my_jobs[job_id].cgminer_work);
              a->my_jobs[job_id].cgminer_work = NULL;
              a->my_jobs[job_id].state = SPONDWORK_STATE_EMPTY;
        }
    }
}


// Remove all work from queue
static void spond_flush_work(struct cgpu_info *cgpu)
{
  printf("FLUSH!!!!!!!!!!!!!!\n");
  struct spond_adapter *a = cgpu->device_data;
  int i;
  mutex_lock(&a->lock);
  spond_dropwork(a);
  mutex_unlock(&a->lock);
}



struct device_drv spondoolies_drv = {
  .drv_id = DRIVER_spondoolies,
  .dname = "Spondoolies",
  .name = "SPN",
  .drv_detect = spondoolies_detect,
  .get_api_stats = spondoolies_api_stats,
  .thread_prepare = spondoolies_prepare,
  .thread_shutdown = spondoolies_shutdown,  
  .hash_work = hash_queued_work,  
  .queue_full = spondoolies_queue_full,  
  .scanwork = spond_scanhash,
  .flush_work = spond_flush_work,
};


