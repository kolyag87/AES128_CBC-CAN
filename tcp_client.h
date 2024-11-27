#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <QObject>
#include <QtNetwork>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QTimer>


#define PORT_TCP                8000
#define IP_SERVER               "192.168.3.100"
#define IP_CLIENT               "192.168.3.90"


class TCP_Client : public QObject
{
    Q_OBJECT
public:
    explicit TCP_Client(QObject *parent = 0);
    ~TCP_Client();

signals:
    void signal_showData(QByteArray);
    void signal_showDecrypt(QByteArray);
    void signal_showPlainText(QByteArray);
    void signal_writeLog(QByteArray);

    void signal_sendToServer();
//    void signal_disconnected();
    void signal_Decrypt(quint8 decrdt[16]);

public slots:
//    void slot_connectToHost();
//    void slot_disconnectFromHost();
    void slot_sendToServer(QByteArray);

private slots:
//    void slot_connected();
//    void slot_disconnected();
    void slot_readyRead();
    void slot_error(QAbstractSocket::SocketError);


    void slot_t_send_to_server_timeout();
//    void slot_t_connectedState_timeout();

public:

    quint16 port, portSend;
    QString ip, ipSend;

//    quint32 time;

//    QTcpSocket *tcp_socket;
    QUdpSocket *udp_socket;    

private:
    quint8 test_data;

//    QByteArray make_hex_log_data(QByteArray data);

    void make_hex_log_data(QByteArray data);
    void make_hex_log_data_tx(QByteArray data);

    QTimer *t_send_to_server;

    QByteArray decryptDt;
    quint8 decrDt[16];
    //QTimer *t_connectedState;




};

#endif // TCP_CLIENT_H
