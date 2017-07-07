/*
 * dns.h
 * DNS header and constants
 *
 * File written by Jiazi Yi
 */

#ifndef DNS_H_
#define DNS_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;

#define BUF_SIZE 65536
#define HOST_NAME_SIZE 100

// query type values
#define TYPE_A 1	//v4


// query class values
#define CLASS_IN 1	// the internet -- that's pretty much we need :)



// DNS header
//                                  1  1  1  1  1  1
// 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                      ID                       |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                QDCOUNT/ZOCOUNT                |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                ANCOUNT/PRCOUNT                |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                NSCOUNT/UPCOUNT                |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//|                    ARCOUNT                    |
//+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
struct dns_header
{
	uint16_t id;
	//	ID              A 16 bit identifier assigned by the program that
	//	                generates any kind of query.  This identifier is copied
	//	                the corresponding reply and can be used by the requester
	//	                to match up replies to outstanding queries.

	
	uint16_t flags;        //Synthesized flags without using bit fields 

	uint16_t qd_count;
		//	QDCOUNT         an unsigned 16 bit integer specifying the number of
		//	                entries in the question section.
	uint16_t an_count;
		//	ANCOUNT         an unsigned 16 bit integer specifying the number of
		//	                resource records in the answer section.
	uint16_t ns_count;
		//	NSCOUNT         an unsigned 16 bit integer specifying the number of name
		//	                server resource records in the authority records
		//	                section.
	uint16_t ar_count;
		//	ARCOUNT         an unsigned 16 bit integer specifying the number of
		//	                resource records in the additional records section.

};
typedef struct dns_header dns_header;




/**
 *  Function written by Jiazi Yi
 *   Transforms the DNS string format to human readable format
 * 	 for example, take '\03'www'\04'abcd'\03'com'\00' , and generate www.abcd.com
 *
 * \param *buff the buffer in which to write
 * \param *name the domain name
 */
void get_domain_name(char *buff, char *name);
//END_SOLUTION


#endif /* DNS_H_ */
