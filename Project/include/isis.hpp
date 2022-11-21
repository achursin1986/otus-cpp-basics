#pragma once
#include <istream>
#include <ostream>
#include <algorithm>
#include <cstring>


static unsigned char ALL_ISS[6] = {0x09, 0x00, 0x2B, 0x00, 0x00, 0x05};
static unsigned char OUR_MAC[6] = {0x00, 0x0c, 0x29, 0x6f, 0x14, 0xbf};
static unsigned char OUR_IP_ADDRESS[4] = { 0x0a, 0x64, 0x00, 0x01 };  
static unsigned char SYS_ID[6] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x01};
static unsigned char AREA[4] = {0x03, 0x49, 0x00, 0x01};
//static unsigned char CIRCUIT_ID = {0x00};
static unsigned char EXTENDED_CIRCUIT_ID[4] = {0x00, 0x00, 0x00, 0x01};
static unsigned char SOURCE_ID[7] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00 };
static unsigned char START_LSP_ID[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static unsigned char END_LSP_ID[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; 


enum level {  l1 = 0x1,
        l2 = 0x2,
        l12 = 0x3 };

enum packet { p2p_hello = 17,
       l2_lsp = 20,
       l2_csnp = 25,
       l2_psnp = 27 };

enum state{  down = 2,
        init = 1,
         up = 0   };





/*
     0            8            16                       31
     ┌────────────┬────────────┬────────────┬────────────┐
     │  IRPD      │ Length     │ Version ID │ ID Length  │
     │            │ Indicator  │            │            │
     ├────────────┼────────────┼────────────┼────────────┤
     │  PDU Type  │  Version   │  Reserved  │ Max Area   │
     │            │            │            │ Addresses  │
     └────────────┴────────────┴────────────┴────────────┘

*/


class isis_header {

public:


isis_header()  { 
        std::fill(rep_, rep_ + sizeof(rep_), 0);
        irpd(0x83);
        version_id(1);
        version(1); 
}

void irpd(unsigned char n) { rep_[0] = n; }
void length_indicator(unsigned char n) { rep_[1] = n; }
void version_id(unsigned char n) { rep_[2] = n; }
void pdu_type(unsigned char n) { rep_[4] = n; }
void version(unsigned char n) { rep_[5] = n; }

unsigned int pdu_type() const { return (unsigned int)rep_[4]; };
unsigned char length_indicator() const { return rep_[1]; }; 
unsigned short size() const { return sizeof(rep_); };

friend std::istream& operator>>(std::istream& is, isis_header& header)
    { return is.read(reinterpret_cast<char*>(header.rep_), 8); }

  friend std::ostream& operator<<(std::ostream& os, const isis_header& header)
    { return os.write(reinterpret_cast<const char*>(header.rep_), 8); }



  private:

  // 2 bytes encode only, make it util func 
  unsigned short decode(int a, int b) const
    { return (rep_[a] << 8) + rep_[b]; }

  void encode(int a, int b, unsigned short n)
  {
    rep_[a] = static_cast<unsigned char>(n >> 8);
    rep_[b] = static_cast<unsigned char>(n & 0xFF);
  }

  unsigned char rep_[8];

};

/*
 
  0            8            16                       31
  ┌────────────┬──────────────────────────────────────┐
  │  Circuit   │           System ID                  │
  │  Type      │                                      │
  ├────────────┴─────────────────────────┬────────────┤
  │             System ID                │ Holding    │
  │                                      │ Timer      │
  ├────────────┬─────────────────────────┼────────────┤
  │ Holding    │ PDU Length              │ Local      │
  │ Timer      │                         │ Circuit ID │
  └────────────┴─────────────────────────┴────────────┘

*/



class isis_hello_header  { 

       public:
        isis_hello_header()  {
               std::fill(rep_, rep_ + sizeof(rep_), 0);
               circuit_type(l2);
               system_id(SYS_ID);
               holding_timer(30);
        }

      void circuit_type(unsigned char n) { rep_[0] = n; }
      void system_id(unsigned char *n) { std::memcpy(&rep_[1], n, sizeof(SYS_ID));}
      void holding_timer(unsigned short n) { encode(7, 8, n); }
      void pdu_length(unsigned short n) { encode(9, 10, n); }
      void local_circuit_id(unsigned char n) { rep_[11] = n; }

      
      unsigned char* system_id() { return &rep_[1]; };
      unsigned short holding_timer() const { return decode(7,8); };
      unsigned short pdu_length() const { return decode(9,10); };

      friend std::istream& operator>>(std::istream& is, isis_hello_header& header)
             { return is.read(reinterpret_cast<char*>(header.rep_), 12); }   

     friend std::ostream& operator<<(std::ostream& os, const isis_hello_header& header)
             { return os.write(reinterpret_cast<const char*>(header.rep_), 12); }
      

      private:

      unsigned short decode(int a, int b) const
                   { return (rep_[a] << 8) + rep_[b]; }

      void encode(int a, int b, unsigned short n)
                   {
                       rep_[a] = static_cast<unsigned char>(n >> 8);
                       rep_[b] = static_cast<unsigned char>(n & 0xFF);
                  } 

      
      unsigned char rep_[12];


};


/* TLVs */



/*

  0            8            16                       31
  ┌────────────┬─────────────┬───────────┬────────────┐
  │  Type      │  Length     │ Adjacency │Extended    │
  │            │             │ State     │Local Cir Id│
  ├────────────┴─────────────┴───────────┼────────────┘
  │   Extended Local Circuit ID          │
  │                                      │
  └──────────────────────────────────────┘

*/

class tlv_240 {

 public:



     tlv_240() {
         std::fill(rep_, rep_ + sizeof(rep_), 0);
         tlv_type(240);
         tlv_length(5);
         //adjacency_state(static_cast<unsigned char>(state::down));
         adjacency_state(down);
         ext_local_circuit_id(EXTENDED_CIRCUIT_ID);
     }     
     void tlv_type(unsigned char n) { rep_[0] = n; }
     void tlv_length(unsigned char n) { rep_[1] = n; }
     void adjacency_state(unsigned char n) { rep_[2] = n; }
     void ext_local_circuit_id(unsigned char *n) { std::memcpy(rep_+3,n, sizeof(EXTENDED_CIRCUIT_ID));}

     unsigned char tlv_type() const { return rep_[0]; };
     unsigned char tlv_length() const { return rep_[1]; };
     unsigned char adjacency_state() const { return rep_[2]; };
     unsigned char* ext_local_circuit_id() { return &rep_[3];};

     friend std::istream& operator>>(std::istream& is, tlv_240& header)
    { return is.read(reinterpret_cast<char*>(header.rep_), 7); }

  friend std::ostream& operator<<(std::ostream& os, const tlv_240& header)
    { return os.write(reinterpret_cast<const char*>(header.rep_), 7); }

 private:
     
     unsigned short decode(int a, int b) const
    { return (rep_[a] << 8) + rep_[b]; }

  void encode(int a, int b, unsigned short n)
  {
    rep_[a] = static_cast<unsigned char>(n >> 8);
    rep_[b] = static_cast<unsigned char>(n & 0xFF);
  }


     unsigned char rep_[7];

};

/*

  0            8            16                       31
  ┌────────────┬─────────────┬───────────┬────────────┐
  │  Type      │  Length     │ Adjacency │Extended    │
  │            │             │ State     │Local Cir Id│
  ├────────────┴─────────────┴───────────┼────────────┤
  │   Extended Local Circuit ID          │ Neighbor   │
  │                                      │ System ID  │
  ├──────────────────────────────────────┴────────────┤
  │          Neighbor System ID                       │
  │                                                   │
  ├────────────┬──────────────────────────────────────┤
  │ Neighbor   │   Neighbor Extended Local Circuit ID │
  │ System ID  │                                      │
  ├────────────┼──────────────────────────────────────┘
  │ Neighbor Ex│
  │ Loc Cir ID │
  └────────────┘

*/
 

class tlv_240_ext {

public:
     enum {  down = 2,
        init = 1,
         up = 0   };

 
     tlv_240_ext() {
         std::fill(rep_, rep_ + sizeof(rep_), 0);
         tlv_type(240);
         tlv_length(15);
         //adjacency_state(static_cast<unsigned char>(state::init));
         adjacency_state(init);
         
     }
     void tlv_type(unsigned char n) { rep_[0] = n; }
     void tlv_length(unsigned char n) { rep_[1] = n; }
     void adjacency_state(unsigned char n) { rep_[2] = n; }
     void ext_local_circuit_id(unsigned char *n) { std::memcpy(rep_+3,n, sizeof(EXTENDED_CIRCUIT_ID));}
     void neighbor_sysid(unsigned char *n) { std::memcpy(rep_+7,n, sizeof(SYS_ID));}
     void ext_neighbor_local_circuit_id(unsigned char *n) { std::memcpy(rep_+13,n, sizeof(EXTENDED_CIRCUIT_ID));}

     unsigned char tlv_type() const { return rep_[0]; };
     unsigned char tlv_length() const { return rep_[1]; };
     unsigned char adjacency_state() const { return rep_[2]; };
     unsigned char* neighbor_sysid() { return &rep_[7]; };
     unsigned char* ext_local_circuit_id() { return &rep_[3];};
     unsigned char* ext_neighbor_local_circuit_id() { return &rep_[13]; };

    friend std::istream& operator>>(std::istream& is, tlv_240_ext& header)
    { return is.read(reinterpret_cast<char*>(header.rep_), 17); }

  friend std::ostream& operator<<(std::ostream& os, const tlv_240_ext& header)
    { return os.write(reinterpret_cast<const char*>(header.rep_), 17); } 
      
    private:
        unsigned short decode(int a, int b) const
                 { return (rep_[a] << 8) + rep_[b]; }

        void encode(int a, int b, unsigned short n)
         {
           rep_[a] = static_cast<unsigned char>(n >> 8);
           rep_[b] = static_cast<unsigned char>(n & 0xFF);
         }
 
        unsigned char rep_[17];


};

/*
  0            8            16                       31
  ┌───────────────────────────────────────────────────┐
  │      Destination MAC                              │
  │                                                   │
  ├─────────────────────────┬─────────────────────────┤
  │  Destination MAC        │    Source MAC           │
  │                         │                         │
  ├─────────────────────────┴─────────────────────────┤
  │          Source MAC                               │
  │                                                   │
  ├─────────────────────────┬────────────┬────────────┤
  │   Length                │  DSAP      │  SSAP      │
  │                         │            │            │
  ├────────────┬────────────┴────────────┴────────────┘
  │ Control    │
  │ Field      │
  └────────────┘
*/


class eth_header {
  /* +llc  */
    public:
         eth_header() {
         std::fill(rep_, rep_ + sizeof(rep_), 0);
         destination(ALL_ISS);
         source(OUR_MAC);
         dsap(0xfe);
         ssap(0xfe);
         control_field(0x03);
         }

         //void destination(unsigned char *n) { encode_array(n, sizeof(n), 0);}
         //void source(unsigned char *n) { encode_array(n, sizeof(n), 6);}
         void destination(unsigned char *n) { std::memcpy(&rep_[0], n, sizeof(ALL_ISS)); }
         void source(unsigned char *n) { std::memcpy(&rep_[6], n, sizeof(OUR_MAC));  }
         void length(unsigned short n) { encode(12, 13, n); }
         void dsap(unsigned char n) { rep_[14] = n; }
         void ssap(unsigned char n) { rep_[15] = n; }
         void control_field(unsigned char n) { rep_[16] = n; }
          
         unsigned short length() const { return decode(12,13); };
         unsigned char* dmac() { return &rep_[0]; };
                  
         friend std::istream& operator>>(std::istream& is, eth_header& header)
                    { return is.read(reinterpret_cast<char*>(header.rep_), 17); }

         friend std::ostream& operator<<(std::ostream& os, const eth_header& header)
                    { return os.write(reinterpret_cast<const char*>(header.rep_), 17); }

    private:

        unsigned short decode(int a, int b) const
            { return (rep_[a] << 8) + rep_[b]; }

        void encode(int a, int b, unsigned short n)
        {
             rep_[a] = static_cast<unsigned char>(n >> 8);
             rep_[b] = static_cast<unsigned char>(n & 0xFF);
        }

        void encode_array(unsigned char* n, int size, int position) 
        {
             for ( int i=0; i<size; ++i ) {
                 rep_[position+i] = n[size+i];                  
             }

        }


        unsigned char rep_[17];
   

};  

/*

  0            8            16                       31
  ┌────────────┬────────────┬────────────┬────────────┐
  │  Type      │  Length    │   NLPID    │  ...       │
  │            │            │            │            │
  └────────────┴────────────┴────────────┴────────────┘

*/



class tlv_129 {


    public:

    tlv_129(){
          std::fill(rep_, rep_ + sizeof(rep_), 0);
          tlv_type(129);
          tlv_length(1);
          nlpid(0xcc);
    }

    void tlv_type(unsigned char n) { rep_[0] = n; }
    void tlv_length(unsigned char n) { rep_[1] = n; }
    void nlpid(unsigned char n) { rep_[2] = n; }

    friend std::istream& operator>>(std::istream& is, tlv_129& header)
                    { return is.read(reinterpret_cast<char*>(header.rep_), 3); }

         friend std::ostream& operator<<(std::ostream& os, const tlv_129& header)
                    { return os.write(reinterpret_cast<const char*>(header.rep_), 3); }
    

    private:

    unsigned char rep_[3];

};


/* 


  0            8            16                       31
  ┌────────────┬────────────┬─────────────────────────┐
  │  Type      │  Length    │    Area Address         │
  │            │            │                         │
  ├────────────┴────────────┼─────────────────────────┘
  │   Area Address          │
  │                         │
  └─────────────────────────┘
*/




class tlv_1 {

    public:
     tlv_1(){
          std::fill(rep_, rep_ + sizeof(rep_), 0);
          tlv_type(1);
          tlv_length(4);
          area(AREA);
    }

    void tlv_type(unsigned char n) { rep_[0] = n; }
    void tlv_length(unsigned char n) { rep_[1] = n; }
    void area(unsigned char *n) { std::memcpy(rep_+2,n, sizeof(AREA));}    

    friend std::istream& operator>>(std::istream& is, tlv_1& header)
                    { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

         friend std::ostream& operator<<(std::ostream& os, const tlv_1& header)
                    { return os.write(reinterpret_cast<const char*>(header.rep_), 6); }

    private:
    unsigned char rep_[6];

};

/*

    0            8            16                       31
    ┌────────────┬────────────┬─────────────────────────┐
    │  Type      │  Length    │   IP address            │
    │            │            │                         │
    ├────────────┴────────────┼─────────────────────────┘
    │   IP address            │
    │                         │
    └─────────────────────────┘
*/



class tlv_132 {
    
    public:
     tlv_132(){
          std::fill(rep_, rep_ + sizeof(rep_), 0);
          tlv_type(132);
          tlv_length(4);
          ip_address(OUR_IP_ADDRESS); 
         
    }

    void tlv_type(unsigned char n) { rep_[0] = n; }
    void tlv_length(unsigned char n) { rep_[1] = n; }
    void ip_address(unsigned char *n) { std::memcpy(rep_+2,n, sizeof(OUR_IP_ADDRESS));}

    friend std::istream& operator>>(std::istream& is, tlv_132& header)
                    { return is.read(reinterpret_cast<char*>(header.rep_), 6); }

         friend std::ostream& operator<<(std::ostream& os, const tlv_132& header)
                    { return os.write(reinterpret_cast<const char*>(header.rep_), 6); }

    private: 
    unsigned char rep_[6];

};




/* 


 0            8            16                       31
 ┌─────────────────────────┬─────────────────────────┐
 │    PDU Length           │    Source-ID            │
 │                         │                         │
 ├─────────────────────────┴─────────────────────────┤
 │     Source-ID                                     │
 │                                                   │
 ├────────────┬────────────┬─────────────────────────┤      │
 │  Type      │  Length    │      LSP ID             │      │  LSP entries TLV9
 │            │            │                         │      │         x
 ├────────────┴────────────┴─────────────────────────┤      │  LSP entry
 │         LSP ID                                    │      │
 │                                                   │      │
 ├─────────────────────────┬─────────────────────────┤      │
 │   LSP ID                │   LSP sequence number   │      │
 │                         │                         │      │
 ├─────────────────────────┼─────────────────────────┤      │
 │  LSP sequence number    │  Remaining lifetime     │      │
 │                         │                         │      │
 ├─────────────────────────┼─────────────────────────┘      │
 │  Checksum               │
 │                         │
 └─────────────────────────┘
                      ...

 */

class isis_psnp_header {

     public:
       isis_psnp_header()  {
            std::fill(rep_, rep_ + sizeof(rep_), 0);            

       }

     unsigned char* system_id() { return &rep_[2]; };
     unsigned short pdu_length() const { return decode(0,1); };
     
 

     friend std::istream& operator>>(std::istream& is, isis_psnp_header& header)
             { return is.read(reinterpret_cast<char*>(header.rep_), 8); }

     friend std::ostream& operator<<(std::ostream& os, const isis_psnp_header& header)
             { return os.write(reinterpret_cast<const char*>(header.rep_), 8); }



     private:

        unsigned short decode(int a, int b) const
                   { return (rep_[a] << 8) + rep_[b]; }

        void encode(int a, int b, unsigned short n)
                   {
                       rep_[a] = static_cast<unsigned char>(n >> 8);
                       rep_[b] = static_cast<unsigned char>(n & 0xFF);
                  }

        unsigned char rep_[8];

};

/* tlv9  */
class tlv_9 { 
        
         public:
            tlv_9() {
                   std::fill(rep_, rep_ + sizeof(rep_), 0);
                   tlv_type(9);
            }


         void tlv_type(unsigned char n) { rep_[0] = n; }
         void tlv_length(unsigned char n) { rep_[1] = n; }
         
         unsigned char tlv_length() const { return rep_[1]; };

         friend std::istream& operator>>(std::istream& is, tlv_9& header)
                    { return is.read(reinterpret_cast<char*>(header.rep_), 2); } 

  friend std::ostream& operator<<(std::ostream& os, const tlv_9& header)
                    { return os.write(reinterpret_cast<const char*>(header.rep_), 2); }


         private:
            unsigned char rep_[2];


};




/* lsp  entry, used with tlv9 */
class lsp_entry { 
       public:
           lsp_entry() {
                  std::fill(rep_, rep_ + sizeof(rep_), 0);
           }

      friend std::istream& operator>>(std::istream& is, lsp_entry& header)
             { return is.read(reinterpret_cast<char*>(header.rep_), 16); }

      friend std::ostream& operator<<(std::ostream& os, const lsp_entry& header)
             { return os.write(reinterpret_cast<const char*>(header.rep_), 16); }

      

       unsigned char* lsp_id() { return &rep_[2]; };


       private:                         
            unsigned char rep_[16];


};

/* 


   0            8            16                       31
   ┌─────────────────────────┬─────────────────────────┐
   │    PDU Length           │    Source-ID            │
   │                         │                         │
   ├─────────────────────────┴─────────────────────────┤
   │     Source-ID                                     │
   │                                                   │
   ├────────────┬──────────────────────────────────────┤
   │  Source-ID │   Start LSP-ID                       │
   │            │                                      │
   ├────────────┴──────────────────────────────────────┤
   │      Start LSP-ID                                 │
   │                                                   │
   ├────────────┬──────────────────────────────────────┤
   │Start LSP-ID│  End LSP-ID                          │
   │            │                                      │
   ├────────────┴──────────────────────────────────────┤
   │               End LSP-ID                          │
   │                                                   │
   ├────────────┬──────────────────────────────────────┘
   │ End LSP-ID │
   │            │
   └────────────┘

                ...              x   LSP entries TLV9

 */

class isis_csnp_header {   

     public:
          isis_csnp_header() {
                std::fill(rep_, rep_ + sizeof(rep_), 0);
                source_id(SOURCE_ID);
                start_lsp_id(START_LSP_ID);
                end_lsp_id(END_LSP_ID);
          }

          void pdu_length(unsigned short n) { encode(0, 1, n); }
          void source_id(unsigned char *n) { std::memcpy(&rep_[2], n, sizeof(SOURCE_ID));}
          void start_lsp_id(unsigned char *n) { std::memcpy(&rep_[9], n, sizeof(START_LSP_ID));}
          void end_lsp_id(unsigned char *n) { std::memcpy(&rep_[18], n, sizeof(END_LSP_ID));}
          
          
           unsigned short pdu_length() const { return decode(0,1); };

          friend std::istream& operator>>(std::istream& is, isis_csnp_header& header)
             { return is.read(reinterpret_cast<char*>(header.rep_), 25); }

          friend std::ostream& operator<<(std::ostream& os, const isis_csnp_header& header)
             { return os.write(reinterpret_cast<const char*>(header.rep_), 25); }



     private:

        unsigned short decode(int a, int b) const
                   { return (rep_[a] << 8) + rep_[b]; }

        void encode(int a, int b, unsigned short n)
                   {
                       rep_[a] = static_cast<unsigned char>(n >> 8);
                       rep_[b] = static_cast<unsigned char>(n & 0xFF);
                  }

        unsigned char rep_[25];

};

/*

     0            8            16                       31
     ┌─────────────────────────┬─────────────────────────┐
     │    PDU Length           │ Remaining-Lifetime      │
     │                         │                         │
     ├─────────────────────────┴─────────────────────────┤
     │     LSP ID                                        │
     │                                                   │
     ├───────────────────────────────────────────────────┤
     │     LDP ID                                        │
     │                                                   │
     ├─────────────────────────┬─────────────────────────┤
     │ Sequence Number         │  Checksum               │
     │                         │                         │
     ├────────────┬────────────┴─────────────────────────┘
     │ Type Block │
     │            │
     └────────────┘

                    ...   TLVs
*/

class isis_lsp_header {  

     public:
        isis_lsp_header() {
               std::fill(rep_, rep_ + sizeof(rep_), 0);
               type_block(0x3);
        }

       void pdu_length(unsigned short n) { encode(0, 1, n); }
       void remaining_lifetime(unsigned short n) { encode(2, 3, n); }
       void lsp_id(unsigned char *n) { std::memcpy(&rep_[4], n, sizeof(START_LSP_ID));}
       void sequnce_num(unsigned char *n) { std::memcpy(&rep_[12], n, 4);}
       void checksum(unsigned short n) { encode(16, 17, n); }
       void type_block(unsigned char n) { rep_[18] = n; }   



      friend std::istream& operator>>(std::istream& is, isis_lsp_header& header)
             { return is.read(reinterpret_cast<char*>(header.rep_), 19); }

          friend std::ostream& operator<<(std::ostream& os, const isis_lsp_header& header)
             { return os.write(reinterpret_cast<const char*>(header.rep_), 19); }
     


     private:

        unsigned short decode(int a, int b) const
                   { return (rep_[a] << 8) + rep_[b]; }

        void encode(int a, int b, unsigned short n)
                   {
                       rep_[b] = static_cast<unsigned char>(n >> 8);
                       rep_[a] = static_cast<unsigned char>(n & 0xFF);
                  }

        unsigned char rep_[19];

};


/* TLVs 
| type | length | value |
*/

class tlv_137 {

         public:
            tlv_137() {
                   std::fill(rep_, rep_ + sizeof(rep_), 0);
                   tlv_type(137);
            }


         void tlv_type(unsigned char n) { rep_[0] = n; }
         void tlv_length(unsigned char n) { rep_[1] = n; }
         void tlv_hostname(unsigned char * n, std::size_t l) { std::memcpy(rep_+2,n,l); }

         unsigned char tlv_length() const { return rep_[1]; };

         friend std::istream& operator>>(std::istream& is, tlv_137& header)
                    { return is.read(reinterpret_cast<char*>(header.rep_), header.rep_[1] + 2); }

         friend std::ostream& operator<<(std::ostream& os, const tlv_137& header)
                    { return os.write(reinterpret_cast<const char*>(header.rep_), header.rep_[1] + 2); }


         private:
             unsigned char rep_[257];  

};






