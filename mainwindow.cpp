#include "main.h"
//#include "aes.h"
#include <QValidator>
#include "AES_128_CBC.h"


//------------------------- tiny AES 128 CBC -----------------------//
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif


#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif

#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif


typedef uint8_t state_t[4][4];


static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


#define getSBoxValue(num) (sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])


// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}


// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}



// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}




// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}


static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }
}

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}



//------------------------------------------------------------


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    setupUi(this);

    setWindowTitle("ECAN-E01S");

    QDir logDir(path_log_directory);
    if(logDir.exists())
        qDebug() << "log directory is exist yet...";
    else
        logDir.mkdir(path_log_directory);

    QString path_logDir = path_log_directory;
    QString log1Filename = log1_filename;
    QString log2Filename = log2_filename;
    log1_path->setText(path_logDir + log1Filename);    
    allowLog1 = false;
    allowLog2 = false;

    txBr_log->document()->setMaximumBlockCount(2000);

    lE_Port->setValidator(new QIntValidator(1, 65535));
//    lE_time->setValidator(new QIntValidator());

    tcp_client = new TCP_Client(this);
    tcp_client_2 = new TCP_Client(this);

    timerCycle = new QTimer(this);

    timerResponse = new QTimer(this);
    timerResponse->setSingleShot(true);

    connect(tcp_client, SIGNAL(signal_showData(QByteArray)),
            SLOT(slot_showData1(QByteArray)));
    connect(tcp_client, SIGNAL(signal_showDecrypt(QByteArray)),
            SLOT(slot_showDecrypt(QByteArray)));
    connect(tcp_client, SIGNAL(signal_Decrypt(quint8)),
            SLOT(slot_Decrypt(quint8)));
//    connect(tcp_client_2, SIGNAL(signal_showDecrypt(QByteArray)),
//            SLOT(slot_showDecrypt(QByteArray)));
    connect(tcp_client, SIGNAL(signal_showPlainText(QByteArray)),
            SLOT(slot_showPlainText(QByteArray)));
    connect(tcp_client_2, SIGNAL(signal_showData(QByteArray)),
            SLOT(slot_showData2(QByteArray)));

    connect(tcp_client, SIGNAL(signal_writeLog(QByteArray)),
            SLOT(slot_writeLog1(QByteArray)));
    connect(tcp_client_2, SIGNAL(signal_writeLog(QByteArray)),
            SLOT(slot_writeLog2(QByteArray)));

    connect(this, SIGNAL(signal_sendToServer(QByteArray)),
            tcp_client, SLOT(slot_sendToServer(QByteArray)));
//    connect(this, SIGNAL(signal_sendToServer(QByteArray)),
//            tcp_client_2, SLOT(slot_sendToServer(QByteArray)));

    connect (timerCycle, SIGNAL(timeout()),SLOT(slot_timerCycle_timeout()));
    connect (timerResponse, SIGNAL(timeout()),SLOT(slot_timerResponse_timeout()));

    //connect(tcp_client, SIGNAL(signal_disconnected()), SLOT(slot_disconnected()));

//    iv.append("5286A5D8B66EFC4A2578B16E9655CA1E");
//    privateKey.append("BA195ED347BFA38B5C8839E467FD1161");

//    uint8_t Iv[16] = {0x3d, 0xd7, 0x13, 0xcb, 0x7a, 0x1e, 0xab, 0x89, 0xdd, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//    uint8_t prKey[16] = {0x96, 0xe9, 0x3b, 0x42, 0x72, 0x15, 0x96, 0x1b, 0x8b, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//    slot_showData2(make_hex_log_data(iv).prepend("iv -> "));
//    slot_showData2(make_hex_log_data(privateKey).prepend("key -> "));

}


MainWindow::~MainWindow()
{
    tcp_client->~TCP_Client();
    tcp_client_2->~TCP_Client();
    qDebug() << "~MainWindow()";
}



void MainWindow::slot_showData1(QByteArray data)
{
    txBr_log->append(QString(data));
}

void MainWindow::slot_showData2(QByteArray data)
{
    txBr_log_2->append(QString(data));
}

void MainWindow::slot_Decrypt(quint8 decrdt[16])
{
//    AES_init_ctx_iv(&ctx, prKey, Iv);
//    AES_CBC_decrypt_buffer(&ctx, Buf, 16);
//    ba.clear();
//    ba.append((const char*) Buf, 16);
//    slot_showData2(make_hex_log_data(ba).prepend("decryptText -> "));
}




void MainWindow::on_pB_clear_clicked()
{
    txBr_log->clear();
    txBr_log_2->clear();
}

void MainWindow::on_log1_button_clicked()
{
    QString path = log1_path->text();

    logFile1.setFileName(path);
    if(logFile1.exists())
        logFile1.remove();

    if(logFile1.open(QFile::ReadWrite | QFile::Text) == false)
        qDebug() << "file " << path << " does not open...";
    else
        allowLog1  = true;
}

void MainWindow::slot_writeLog1(QByteArray data)
{
    if(allowLog1 == true)
    {
        logFile1.write(data + "\r\n");
    }
}


void MainWindow::on_stopLog1_button_clicked()
{
    allowLog1 = false;
    logFile1.close();
}



void MainWindow::on_pB_set_clicked()
{
    tcp_client->port = lE_Port->text().toInt();
    tcp_client->ip = lE_IP->text();
    tcp_client->udp_socket->disconnectFromHost();
    tcp_client->udp_socket->bind(QHostAddress(tcp_client->ip), tcp_client->port);

    qDebug() << tcp_client->ip << tcp_client->port;
}


void MainWindow::on_pB_stop_clicked()
{
    tcp_client->udp_socket->disconnectFromHost();

    qDebug() << "STOP" << tcp_client->ip << tcp_client->port;
}


void MainWindow::on_pB_set_3_clicked()
{
    tcp_client->portSend = lE_Port_3->text().toInt();
    tcp_client->ipSend = lE_IP_3->text();
}


void MainWindow::on_pB_send_1_clicked()
{
    QByteArray bd;

    quint8 bt = 0;

    //Заполняем 0
//    bd.fill(0, 8);

    if (chB_extID_1->checkState() == Qt::Checked)
        bt |= (1<<7);               //Ext ID
    bt |= lE_DLC_1->text().toInt();
    bd.append(bt);

//    quint32 id = lE_ID_1->text().toUtf8();
    bd.append(QByteArray::fromHex(lE_ID_1->text().toUtf8()));

    bd.insert(5, 8, 0);

    quint8 dlc = lE_DLC_1->text().toInt();
    if (dlc > 0)
    {
        bd.replace(5, 1, QByteArray::fromHex(lE_D0_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(6, 1, QByteArray::fromHex(lE_D1_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(7, 1, QByteArray::fromHex(lE_D2_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(8, 1, QByteArray::fromHex(lE_D3_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(9, 1, QByteArray::fromHex(lE_D4_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(10, 1, QByteArray::fromHex(lE_D5_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(11, 1, QByteArray::fromHex(lE_D6_1->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(12, 1, QByteArray::fromHex(lE_D7_1->text().toUtf8()));
        dlc--;
    }

    emit signal_sendToServer(bd);

    qDebug() << bt << dlc << bd;

}




void MainWindow::on_pB_stop_3_clicked()
{
    timerCycle->stop();

    qDebug() << "STOP cycle timer";
}




void MainWindow::on_pB_send_10_clicked()
{
    QByteArray bd;

    quint8 bt = 0;

    //Заполняем 0
//    bd.fill(0, 8);

    if (chB_extID_10->checkState() == Qt::Checked)
        bt |= (1<<7);               //Ext ID
    bt |= lE_DLC_10->text().toInt();
    bd.append(bt);

//    quint32 id = lE_ID_1->text().toUtf8();
    bd.append(QByteArray::fromHex(lE_ID_10->text().toUtf8()));

    bd.insert(5, 8, 0);

    quint8 dlc = lE_DLC_10->text().toInt();
    if (dlc > 0)
    {
        bd.replace(5, 1, QByteArray::fromHex(lE_D0_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(6, 1, QByteArray::fromHex(lE_D1_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(7, 1, QByteArray::fromHex(lE_D2_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(8, 1, QByteArray::fromHex(lE_D3_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(9, 1, QByteArray::fromHex(lE_D4_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(10, 1, QByteArray::fromHex(lE_D5_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(11, 1, QByteArray::fromHex(lE_D6_10->text().toUtf8()));
        dlc--;
    }
    if (dlc > 0)
    {
        bd.replace(12, 1, QByteArray::fromHex(lE_D7_10->text().toUtf8()));
        dlc--;
    }

    emit signal_sendToServer(bd);

    qDebug() << bt << dlc << bd;

}


void MainWindow::slot_showPlainText(QByteArray dt)
{
    QByteArray ba;
//    slot_showData2(ba.prepend("\rencryptPack -> "));
    slot_showData2(make_hex_log_data(dt).prepend("\rPlainText -> "));

    uint8_t Buf[16];

    for (uint8_t i=0; i<16; i++)
        Buf[i] = (uint8_t)(dt.at(i));

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_encrypt_buffer(&ctx, Buf, 16);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("EncryptText_tiny -> "));

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_decrypt_buffer(&ctx, Buf, 16);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("DecryptText_tiny -> "));

    //------------------------ AES_128_CBC.h -----------------------------//

    for (uint8_t i=0; i<16; i++)
        Buf[i] = (uint8_t)(dt.at(i));

    AES_CTX ctx_;
    AES_EncryptInit(&ctx_, prKey, Iv);
    AES_Encrypt(&ctx_, Buf, Buf);

    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("encryptText_aes -> "));

    AES_DecryptInit(&ctx_, prKey, Iv);
    AES_Decrypt(&ctx_, Buf, Buf);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("decryptText_aes -> "));
}



void MainWindow::slot_timerResponse_timeout()
{
    QByteArray bd, ba;
    quint8 bt = 0;

    //Std ID
    bt |= 8;
//    bd.append(bt);

//    quint32 id = 0x776;
//    bd.append((uint8_t)(id >> 24));
//    bd.append((uint8_t)(id >> 16));
//    bd.append((uint8_t)(id >> 8));
//    bd.append((uint8_t)id);
//    //Freim 1
//    bd.append(0x55);
//    bd.append(0x8D);
//    bd.append(0x91);
//    bd.append(0xEF);
//    bd.append(0x51);
//    bd.append(0x1A);
//    bd.append(0x10);
//    bd.append(0x05);

//    emit signal_sendToServer(bd);

    //Freim 2
//    bd.clear();
//    bt |= 8;
//    bd.append(bt);

//    id = 0x777;
//    bd.append((uint8_t)(id >> 24));
//    bd.append((uint8_t)(id >> 16));
//    bd.append((uint8_t)(id >> 8));
//    bd.append((uint8_t)id);
//    bd.append(0x12);
//    bd.append(0x34);
//    bd.append(0x56);
//    bd.append(0x78);
//    bd.append(0x9A);
//    bd.append(0xBC);
//    bd.append(0xDE);
//    bd.append(0xFF);

    uint8_t Buf[16];

    Buf[0] = 0x27;
    Buf[1] = 0x35;
    Buf[2] = 0x44;
    Buf[3] = 0xAB;
    Buf[4] = 0x51;
    Buf[5] = 0x1A;
    Buf[6] = 0x61;
    Buf[7] = 0x69;
    Buf[8] = 0x12;
    Buf[9] = 0x29;
    Buf[10] = 0x56;
    Buf[11] = 0x28;
    Buf[12] = 0x9A;
    Buf[13] = 0x91;
    Buf[14] = 0xB6;
    Buf[15] = 0x89;

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_encrypt_buffer(&ctx, Buf, 16);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("Tx_EncryptText_tiny -> "));

    //Freim 1
    uint32_t id = 0x776;
    bd.append(bt).append((uint8_t)(id>>24)).append((uint8_t)(id>>16)).append((uint8_t)(id>>8)).append((uint8_t)(id)).append(ba.mid(0, 8));
    //Freim 2
    id = 0x777;
    bd.append(bt).append((uint8_t)(id>>24)).append((uint8_t)(id>>16)).append((uint8_t)(id>>8)).append((uint8_t)(id)).append(ba.mid(8, 8));

    emit signal_sendToServer(bd);
//    qDebug() << "TimerResponse";

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_decrypt_buffer(&ctx, Buf, 16);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("Tx_DecryptText_tiny -> "));

}



void MainWindow::slot_showDecrypt(QByteArray dt)
{
    QByteArray ba;
//    slot_showData2(ba.prepend("\rencryptPack -> "));
    slot_showData2(make_hex_log_data(dt).prepend("\rreceivePack -> "));

    uint8_t Buf[16];

    for (uint8_t i=0; i<16; i++)
        Buf[i] = (uint8_t)(dt.at(i));

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_decrypt_buffer(&ctx, Buf, 16);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("decryptText_tiny -> "));

    //------------------------ AES_128_CBC.h -----------------------------//

    for (uint8_t i=0; i<16; i++)
        Buf[i] = (uint8_t)(dt.at(i));

    AES_CTX ctx_;
    AES_DecryptInit(&ctx_, prKey, Iv);
    AES_Decrypt(&ctx_, Buf, Buf);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("decryptText_aes -> "));

    timerResponse->start(24);
}



void MainWindow::on_pB_cipher_clicked()
{
    QByteArray ba;
    ba.append(QByteArray::fromHex(lE_B_0->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_1->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_2->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_3->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_4->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_5->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_6->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_7->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_8->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_9->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_10->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_11->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_12->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_13->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_14->text().toUtf8()));
    ba.append(QByteArray::fromHex(lE_B_15->text().toUtf8()));

    slot_showData2(make_hex_log_data(ba).prepend("\rplainText -> "));

    uint8_t Buf[16];

    for (uint8_t i=0; i<16; i++)
        Buf[i] = (uint8_t)(ba.at(i));

//    ba.clear();
//    ba.append("iv -> ").append(iv);
//    slot_showData2(ba);

//    ba.clear();
//    ba.append("key -> ").append(privateKey);
//    slot_showData2(ba);

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_encrypt_buffer(&ctx, Buf, 16);

    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("encryptText -> "));

    AES_init_ctx_iv(&ctx, prKey, Iv);
    AES_CBC_decrypt_buffer(&ctx, Buf, 16);
    ba.clear();
    ba.append((const char*) Buf, 16);
    slot_showData2(make_hex_log_data(ba).prepend("decryptText -> "));

    //------------------------ AES_128_CBC.h -----------------------------//

//    AES_CTX ctx_;
//    AES_EncryptInit(&ctx_, prKey, Iv);
//    AES_Encrypt(&ctx_, Buf, Buf);

//    ba.clear();
//    ba.append((const char*) Buf, 16);
//    slot_showData2(make_hex_log_data(ba).prepend("encryptText -> "));

//    AES_DecryptInit(&ctx_, prKey, Iv);
//    AES_Decrypt(&ctx_, Buf, Buf);
//    ba.clear();
//    ba.append((const char*) Buf, 16);
//    slot_showData2(make_hex_log_data(ba).prepend("decryptText -> "));

}




//-----------------------------------------------------------------------------------//
//Переводим данные в видимый hex формат

/*QByteArray*/
QByteArray MainWindow::make_hex_log_data(QByteArray data)
{
    QByteArray ba, bd;
    quint8 l, lenw;
//    QDateTime date;

    ba = data.toHex();
//    lenw = ba.length();
//    for (int i=0; i < lenw; i++)
//    {
//        ba.insert(i*3, 0x20);
//    }


//        data.remove(0,13);

    //    ba.append(data.toHex());

//        l = (ba.left(2).toInt()) & 0x0F;
//        lenw = ba.length();
//        for (int i=0; i < lenw; i++)
//        {
//            ba.insert(i*3, 0x20);
//        }


//        ba.insert(3, "x_");
//        ba.insert(17, " _");
//        if (l < 8)
//            ba.remove(20+3*l, 3*(8-l));
//        ba.remove(0, 3);

//        bd.append(date.currentDateTime().toString("dd.MM.yyyy hh:mm:ss.zzz"));
//        bd.append("          ");
//        bd.append(ba);
//        bd.append("\r");

//        slot_showData2(ba);


    return ba;
}




//void MainWindow::on_pB_Send_clicked()
//{
//    emit signal_sendToServer();
//}


//void MainWindow::slot_disconnected()
//{
//    lE_IP->setEnabled(true);
//    lE_Port->setEnabled(true);
//    lE_time->setEnabled(true);
//}




//--------------------- tiny AES 128 CBC --------------------------------


void MainWindow::AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}

void MainWindow::AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}


void MainWindow::AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}


void MainWindow::AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}


void MainWindow::AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  size_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }
}


