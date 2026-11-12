; IronTLS shared constants and structure offsets (Win64, NASM)
; Must match include/irontls.h exactly.

%define SHA_H         0
%define SHA_TOTAL     32
%define SHA_BUFLEN    40
%define SHA_BUF       48
%define SHA_SIZE      112

%define HMAC_INNER    0
%define HMAC_OPAD     112
%define HMAC_SIZE     176

%define AE_KEY        0
%define AE_IV         16
%define AE_PAD        28
%define AE_SEQ        32
%define AE_SIZE       40

%define CTX_ROLE          0
%define CTX_STATE         4
%define CTX_ERR           8
%define CTX_FLAGS         12
%define CTX_PSK_LEN       16
%define CTX_ID_LEN        20
%define CTX_RX_LEN        24
%define CTX_TX_LEN        28
%define CTX_HS_LEN        32
%define CTX_APP_LEN       36
%define CTX_APP_OFF       40
%define CTX_PSK           48
%define CTX_IDENTITY      80
%define CTX_TRANSCRIPT    208
%define CTX_C_HS          320
%define CTX_S_HS          360
%define CTX_C_AP          400
%define CTX_S_AP          440
%define CTX_EARLY         480
%define CTX_MASTER        512
%define CTX_C_HS_SECRET   544
%define CTX_S_HS_SECRET   576
%define CTX_RX            608
%define CTX_TX            16992
%define CTX_HS            33376
%define CTX_APP           66144
%define CTX_SCRATCH       82528

%define IT_RX_CAP         16384
%define IT_TX_CAP         16384
%define IT_HS_CAP         32768
%define IT_APP_CAP        16384
%define IT_SCRATCH_CAP    16384
%define IT_MAX_PSK        32
%define IT_MAX_IDENTITY   128

%define ROLE_CLIENT       0
%define ROLE_SERVER       1

%define ST_INIT           0
%define ST_CH_SENT        1
%define ST_WAIT_CH        2
%define ST_WAIT_CFIN      3
%define ST_WAIT_SFIN      4
%define ST_ESTABLISHED    5
%define ST_ERROR          255

%define FLAG_HS_KEYS      1
%define FLAG_APP_KEYS     2

%define IT_OK             0
%define IT_NEED_MORE      1
%define IT_DONE           2
%define IT_ERR_ARGS      -1
%define IT_ERR_STATE     -2
%define IT_ERR_PROTOCOL  -3
%define IT_ERR_CRYPTO    -4
%define IT_ERR_BUFFER    -5
%define IT_ERR_IO        -6
