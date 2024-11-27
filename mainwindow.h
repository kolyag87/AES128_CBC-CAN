#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFile>
#include <QDir>
#include <QString>
#include <QDebug>
#include <QTimer>
#include "ui_mainwindow.h"
#include "tcp_client.h"
//#include "aes.h"

#define path_log_directory "../logs/"
#define log1_filename "can1.txt"
#define log2_filename "can2.txt"

#define PERIOD_CYCLE_SEND   1000        //msec


//------ AES --------------------------------

#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif


struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
//#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
  uint8_t Iv[AES_BLOCKLEN];
//#endif
};






//-----------------------------------------



class MainWindow : public QMainWindow, Ui::MainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();


signals:
//    void signal_connectToHost();
//    void signal_disconnectFromHost();
    void signal_sendToServer(QByteArray dt);

private slots:

    void slot_showData1(QByteArray data);
    void slot_showData2(QByteArray data);
    void slot_writeLog1(QByteArray data);
    void slot_showDecrypt(QByteArray);
    void slot_showPlainText(QByteArray);
    void slot_Decrypt(quint8 decrdt[16]);
    void slot_timerResponse_timeout();

//    void slot_disconnected();

//    void on_pB_connect_clicked();

//    void on_pB_disconnect_clicked();

    void on_pB_set_clicked();
    void on_pB_stop_clicked();

//    void on_pB_Send_clicked();

    void on_pB_send_1_clicked();    

    void on_pB_send_10_clicked();

    void on_pB_set_3_clicked();


    void on_pB_clear_clicked();    

    void on_log1_button_clicked();

    void on_stopLog1_button_clicked();

    void on_pB_stop_3_clicked();
    
    void on_pB_cipher_clicked();

private:
    TCP_Client *tcp_client;
    TCP_Client *tcp_client_2;
    bool allowLog1, allowLog2;
    QFile logFile1;
    QTimer *timerCycle;    
    QTimer *timerResponse;

public:
//    QByteArray iv;
//    QByteArray privateKey;

    uint8_t Iv[16] = {0x3d, 0xd7, 0x13, 0xcb, 0x7a, 0x1e, 0xab, 0x89, 0xdd, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t prKey[16] = {0x96, 0xe9, 0x3b, 0x42, 0x72, 0x15, 0x96, 0x1b, 0x8b, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    QByteArray make_hex_log_data(QByteArray data);

    //-------------------- tiny AES CBC -------------------------//
    AES_ctx ctx;

public:
    void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
    void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
    void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

    void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length);
    void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
};

#endif // MAINWINDOW_H
