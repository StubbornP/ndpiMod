

//
// Created by Stubborn on 4/5/17.
//


#include <stdlib.h>
#include<libndpi-1.8.0/libndpi/ndpi_api.h>


#include "modNDPI.h"
#include"ndpi_util.h"


#define DECODE_TUNNEL 0
#define QUIET_MODE 1
#define PROTO_FILE NULL
#define PROTO_GUESS 1

lua_State *current_Machine;

struct context {
    struct ndpi_workflow * workflow;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];
};

u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0,link_type;

static  struct ndpi_workflow_prefs prefs;
static  struct context main_context;

static u_int16_t node_guess_undetected_protocol(struct ndpi_flow_info *flow) {

    flow->detected_protocol = ndpi_guess_undetected_protocol(main_context.workflow->ndpi_struct,
                                                             flow->protocol,
                                                             ntohl(flow->lower_ip),
                                                             ntohs(flow->lower_port),
                                                             ntohl(flow->upper_ip),
                                                             ntohs(flow->upper_port));
    printf("Guess state: %u\n", flow->detected_protocol.app_protocol);
    if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
        main_context.workflow->stats.guessed_flow_protocols++;

    return(flow->detected_protocol.app_protocol);
}

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if((!flow->detection_completed) && flow->ndpi_flow)
            flow->detected_protocol = ndpi_detection_giveup(main_context.workflow->ndpi_struct, flow->ndpi_flow);

        if(PROTO_GUESS) {
            if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
                node_guess_undetected_protocol(flow);
                // printFlow(thread_id, flow);
                printf("Flow detected run into function(%s):%s\n",__func__,
                       ndpi_get_proto_name(main_context.workflow->ndpi_struct,flow->detected_protocol.app_protocol));
            }
        }

        process_ndpi_collected_info(main_context.workflow, flow);
        main_context.workflow->stats.protocol_counter[flow->detected_protocol.app_protocol]       += flow->packets;
        main_context.workflow->stats.protocol_counter_bytes[flow->detected_protocol.app_protocol] += flow->bytes;
        main_context.workflow->stats.protocol_flows[flow->detected_protocol.app_protocol]++;
    }
}

static void idle_flow_scan_callback(const void *node, ndpi_VISIT which, int depth, void *_) {

    struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;

    // return if the budget is ful-filled
    if(main_context.num_idle_flows == IDLE_SCAN_BUDGET)
        return;

    if((which == ndpi_preorder) || (which == ndpi_leaf)) {

        // Insert an expired flow into the budget-list
        if(flow->last_seen + MAX_IDLE_TIME < main_context.workflow->last_time) {

            /* update stats */
            node_proto_guess_walker(node, which, depth, NULL );

            ndpi_free_flow_info_half(flow);
            main_context.workflow->stats.ndpi_flow_count--;

            main_context.idle_flows[main_context.num_idle_flows++] = flow;
        }
    }
}

static void on_protocol_discovered_callback(struct ndpi_workflow * workflow,
                                            struct ndpi_flow_info * flow,
                                            void * _) {
    if( !QUIET_MODE ){
        if(PROTO_GUESS) {

            if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
                flow->detected_protocol.app_protocol = node_guess_undetected_protocol(flow),
                        flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
            }
        }

//        printFlow(thread_id, flow);
    }
    printf("Flow detected run into function(%s):%s \n",__func__,
           ndpi_get_proto_name(main_context.workflow->ndpi_struct,flow->detected_protocol.app_protocol));
}

void init_workflow(){

    NDPI_PROTOCOL_BITMASK all;

    memset(&prefs, 0, sizeof(prefs));
    prefs.decode_tunnels = DECODE_TUNNEL;
    prefs.num_roots = NUM_ROOTS;
    prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
    prefs.quiet_mode = QUIET_MODE;

    memset( &main_context, 0, sizeof(struct context));
    main_context.workflow = ndpi_workflow_init(&prefs, NULL);


    /* Preferences */
    main_context.workflow->ndpi_struct->http_dont_dissect_response = 0;
    main_context.workflow->ndpi_struct->dns_dissect_response = 0;

    ndpi_workflow_set_flow_detected_callback(main_context.workflow,
                                             on_protocol_discovered_callback, NULL);

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(main_context.workflow->ndpi_struct, &all);

    // clear memory for results
    memset(main_context.workflow->stats.protocol_counter, 0, sizeof(main_context.workflow->stats.protocol_counter));
    memset(main_context.workflow->stats.protocol_counter_bytes, 0, sizeof(main_context.workflow->stats.protocol_counter_bytes));
    memset(main_context.workflow->stats.protocol_flows, 0, sizeof(main_context.workflow->stats.protocol_flows));

    if(PROTO_FILE != NULL)
        ndpi_load_protocols_file(main_context.workflow->ndpi_struct, PROTO_FILE);

}

static void packet_callback(u_char *args, const struct pcap_pkthdr *header,
                            const u_char *packet) {

    // Overflow check
    uint8_t *packet_checked = malloc(header->caplen);
    memcpy(packet_checked, packet, header->caplen);

    // Now we deliver the packet to the workflow
    ndpi_workflow_process_packet(main_context.workflow, header, packet_checked);


    // this GC process should be optimized latter *********************************************

    // trigger idle flow clean process in a constant interval
    if(main_context.last_idle_scan_time + IDLE_SCAN_PERIOD < main_context.workflow->last_time) {
        // Search all flows and fill the idle flow budget
        ndpi_twalk(main_context.workflow->ndpi_flows_root[main_context.idle_scan_idx], idle_flow_scan_callback, NULL);
        // free all the flows
        while (main_context.num_idle_flows > 0) {

            printf("Here we run into Flow GC with idel flow = %d, idex_scan_index = %d"
                    ,main_context.num_idle_flows
                    ,main_context.idle_scan_idx);

            ndpi_tdelete(main_context.idle_flows[--main_context.num_idle_flows],
                         &main_context.workflow->ndpi_flows_root[main_context.idle_scan_idx],
                         ndpi_workflow_node_cmp);

            /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
            ndpi_free_flow_info_half(main_context.idle_flows[main_context.num_idle_flows]);
            ndpi_free(main_context.idle_flows[main_context.num_idle_flows]);
        }

        //switch to the next b-tree and refersh the time
        if(++main_context.idle_scan_idx == main_context.workflow->prefs.num_roots) main_context.idle_scan_idx = 0;
        main_context.last_idle_scan_time = main_context.workflow->last_time;
    }

    /* check for buffer changes */
    if(memcmp(packet, packet_checked, header->caplen) != 0)
        printf("INTERNAL ERROR: ingress packet was modified by nDPI: this should not happen [thread_id=%u, packetId=%lu]\n",
               0, (unsigned long)main_context.workflow->stats.raw_packet_count);
    free(packet_checked);
}

int init( lua_State *L){

    lua_Integer link = luaL_checkinteger( L, -1 );

    link_type = (uint32_t)link;

    init_workflow();

    return 0;
}
int process( lua_State *L){

    lua_Integer  packet = luaL_checkinteger( L, -5 );
    lua_Integer  len = luaL_checkinteger( L, -4 );
    lua_Integer  caplen = luaL_checkinteger( L, -3 );
    lua_Integer  ts_sec = luaL_checkinteger( L, -2 );
    lua_Integer  ts_usec = luaL_checkinteger( L, -1 );

    current_Machine = L;

    lua_newtable( L );

    struct pcap_pkthdr pkthdr;

    pkthdr.len = (unsigned int)len;
    pkthdr.caplen = (unsigned int)caplen;
    pkthdr.ts.tv_sec = ts_sec;
    pkthdr.ts.tv_usec = ts_usec;

    packet_callback( 0, &pkthdr, ( u_char* )packet);

    current_Machine = NULL;

    return 1;
}

luaL_Reg functionTable[] = {

        { "modNDPIInit", init},
        { "modNDPIProcess", process},
};

int luaopen_modNDPI( lua_State *L ){

    printf("call1");

    lua_newtable( L );
    printf("call2");
    luaL_setfuncs( L, functionTable, 0);
    printf("call3");
    return 1;
}