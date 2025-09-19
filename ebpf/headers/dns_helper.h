
#include "tcp_helper.h"

#define READ_KERN(ptr)                                      \
    ({                                                      \
        typeof(ptr) _val;                                   \
        __builtin_memset((void*)&_val, 0, sizeof(_val));    \
        bpf_probe_read((void*)&_val, sizeof(_val), &(ptr)); \
        _val;                                               \
    })

#define READ_USER(ptr)                                           \
    ({                                                           \
        typeof(ptr) _val;                                        \
        __builtin_memset((void*)&_val, 0, sizeof(_val));         \
        bpf_probe_read_user((void*)&_val, sizeof(_val), &(ptr)); \
        _val;                                                    \
    })

// #define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
// #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define ctx_ptr(field) (void*)(long)(field)

#define AF_INET 2
#define AF_INET6 10

#define MAX_PERCPU_BUFSIZE 10240
#define MAX_STR_ARR_ELEM 40
#define MAX_STRING_SIZE 4096

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */
#define MAX_DNS_NAME_LENGTH 256

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1. Format

All communications inside of the domain protocol are carried in a single
format called a message.  The top level format of message is divided
into 5 sections (some of which are empty in certain cases) shown below:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
*/

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1.1. Header section format

The header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ID              A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.

QR              A one bit field that specifies whether this message is a
                query (0), or a response (1).

OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use

AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit
*/
struct dns_header {
    uint16_t transaction_id;
    uint8_t qr : 1;      // Query/response flag
    uint8_t opcode : 4;  // Opcode
    uint8_t aa : 1;      // Authoritive answer
    uint8_t tc : 1;      // Truncated
    uint8_t rd : 1;      // Recursion desired
    uint8_t ra : 1;      // Recursion available
    uint8_t z : 3;       // Z reserved bit
    uint8_t rcode : 4;   // Response code
    uint16_t q_count;    // Number of questions
    uint16_t ans_count;  // Number of answer RRs
    uint16_t auth_count; // Number of authority RRs
    uint16_t add_count;  // Number of resource RRs
} __attribute__((packed));
;

struct ar_hdr {
    uint8_t name;
    uint16_t type;
    uint16_t size;
    uint32_t ex_rcode;
    uint16_t rcode_len;
} __attribute__((packed));

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1.2. Question section format

The question section is used to carry the "question" in most queries,
i.e., the parameters that define what is being asked.  The section
contains QDCOUNT (usually 1) entries, each of the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:
QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.

QTYPE           a two octet code which specifies the type of the query.
                The values for this field include all codes valid for a
                TYPE field, together with some more general codes which
                can match more than one type of RR.


Mockapetris                                                    [Page 28]

RFC 1035        Domain Implementation and Specification    November 1987


QCLASS          a two octet code that specifies the class of the query.
                For example, the QCLASS field is IN for the Internet.
*/
struct dns_question {
    u8 name[MAX_DNS_NAME_LENGTH];
    uint16_t record_type;
    uint16_t class;
};

struct dns_event {
    u64 ts;
    u16 r_type;
    u8 is_matched;
    char name[MAX_DNS_NAME_LENGTH];
};

struct a_record {
    __be32 ip_addr;
    uint32_t ttl;
};

/*
ref: https://www.ietf.org/rfc/rfc1035.txt
4.1.3. Resource record format

The answer, authority, and additional sections all share the same
format: a variable number of resource records, where the number of
records is specified in the corresponding count field in the header.
Each resource record has the following format:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

NAME            a domain name to which this resource record pertains.

TYPE            two octets containing one of the RR type codes.  This
                field specifies the meaning of the data in the RDATA
                field.

CLASS           two octets which specify the class of the data in the
                RDATA field.

TTL             a 32 bit unsigned integer that specifies the time
                interval (in seconds) that the resource record may be
                cached before it should be discarded.  Zero values are
                interpreted to mean that the RR can only be used for the
                transaction in progress, and should not be cached.

RDLENGTH        an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.

RDATA           a variable length string of octets that describes the
                resource.  The format of this information varies
                according to the TYPE and CLASS of the resource record.
                For example, the if the TYPE is A and the CLASS is IN,
                the RDATA field is a 4 octet ARPA Internet address.
*/
struct dns_response {
    uint16_t query_pointer;
    uint16_t record_type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_length;
} __attribute__((packed));

static __always_inline void* skip_name(void* cursor, void* data_end) {
    unsigned char* p = cursor;
    /* Bounded label walk to satisfy the verifier */
    // #pragma unroll
    for (int i = 0; i < 8; i++) {
        if ((void*)(p + 1) > data_end)
            return 0;
        u8 len = *p;
        /* End of name */
        if (len == 0)
            return p + 1;
        /* Compression pointer (two bytes) */
        if ((len & 0xC0) == 0xC0) {
            if ((void*)(p + 2) > data_end)
                return 0;
            return p + 2;
        }
        /* Regular label */
        p += 1 + len;
        if ((void*)p > data_end)
            return 0;
    }
    return 0;
}

// Parse query and return query length
static inline int parse_query(struct __sk_buff* ctx, void* query_start, struct dns_question* q) {
    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = query_start;

    /* Zero out the name to keep a stable key layout without byte-by-byte copy */
    __builtin_memset(&q->name[0], 0, sizeof(q->name));
    q->record_type = 0;
    q->class = 0;

    /* Use verifier-friendly label skipping instead of per-byte iteration */
    void* name_next = skip_name(cursor, data_end);
    if (!name_next) {
        return -1;
    }

    /* Read QTYPE and QCLASS (2 bytes each) */
    void* tail = name_next + 4;
    if (tail > data_end) {
        return -1;
    }
    q->record_type = bpf_ntohs(*(uint16_t*)(name_next + 0));
    q->class = bpf_ntohs(*(uint16_t*)(name_next + 2));

    /* Return total query length: skipped NAME + 4 bytes */
    return (int)((long)tail - (long)query_start);
}

#define DNS_MAX_ANCOUNT 4
struct cache_record {
    u32 ip[DNS_MAX_ANCOUNT];
    u32 ttl[DNS_MAX_ANCOUNT];
} __attribute__((packed));