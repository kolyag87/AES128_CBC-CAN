#include "main.h"

#include "testrawdata.h"

TCP_Client::TCP_Client(QObject *parent) : QObject(parent)
{
    port = PORT_TCP;
    ip = IP_SERVER;
    ipSend = IP_CLIENT;
    portSend = PORT_TCP;
    decrDt[16];

//    tcp_socket = new QTcpSocket(this);

    udp_socket = new QUdpSocket(this);
//    QHostAddress address;
//    address.setAddress(ip);
//    udp_socket->bind(QHostAddress(ip), 8881);
//    udp_socket->bind(QHostAddress::LocalHost, 10001);

    connect(udp_socket, SIGNAL(readyRead()), SLOT(slot_readyRead()));

//    connect(tcp_socket, SIGNAL(connected()), SLOT(slot_connected()) );
//    connect(tcp_socket, SIGNAL(readyRead()), SLOT(slot_readyRead()));
//    connect(tcp_socket, SIGNAL(error(QAbstractSocket::SocketError)),
//            SLOT(slot_error(QAbstractSocket::SocketError)));
//    connect(tcp_socket, SIGNAL(disconnected()), SLOT(slot_disconnected()));

//    test_data = 0;


//    t_send_to_server = new QTimer(this);
//    connect(t_send_to_server, SIGNAL(timeout()), SLOT(slot_t_send_to_server_timeout()));

//    t_connectedState = new QTimer(this);
//    connect(t_connectedState, SIGNAL(timeout()), SLOT(slot_t_connectedState_timeout()));

//    connect(this, SIGNAL(signal_sendToServer()), SLOT(slot_sendToServer()));

}



TCP_Client::~TCP_Client()
{
//    tcp_socket->disconnectFromHost();
//    tcp_socket->waitForDisconnected();
//    tcp_socket->deleteLater();

    qDebug() << "~TCP_Client()";
}



//void TCP_Client::slot_connectToHost()
//{
////    t_send_to_server->start(3000);
//}



//void TCP_Client::slot_disconnectFromHost()
//{
//    t_send_to_server->stop();
//}




void TCP_Client::slot_readyRead()
{
    QByteArray bd;

    while (udp_socket->hasPendingDatagrams())
    {
        bd.resize(udp_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        udp_socket->readDatagram(bd.data(), bd.size(),
                                &sender, &senderPort);

//        emit signal_showData(make_hex_log_data("receive\n\r"));
//        emit signal_showData(make_hex_log_data(bd));
        make_hex_log_data(bd);
    }


}


void TCP_Client::slot_error(QAbstractSocket::SocketError err)
{
    QString strError =
    "Error: " + (err == QAbstractSocket::HostNotFoundError ?
    "The host was not found." :
    err == QAbstractSocket::RemoteHostClosedError ?
    "The remote host is closed." :
    err == QAbstractSocket::ConnectionRefusedError ?
    "The connection was refused." :
    QString(udp_socket->errorString())
    );
    emit signal_showData(strError.toLocal8Bit());

}




void TCP_Client::slot_sendToServer(QByteArray data)
{
//    QByteArray bd;

//    bd = testrawdata.fromHex(testrawdata);

    udp_socket->writeDatagram(data.data(), data.length(), QHostAddress(ipSend), portSend);

    qDebug() << data << ipSend << portSend;

//    emit signal_showData(make_hex_log_data(data));
    make_hex_log_data_tx(data);

}



void TCP_Client::make_hex_log_data_tx(QByteArray data)
{
    quint8 l, lenw;
    QDateTime date;
    QByteArray ba, bd;

//    data.remove(0,13);
    bd.clear();
    ba.append(data.toHex());

    l = (ba.left(2).toInt()) & 0x0F;
    lenw = ba.length();
    for (int i=0; i < lenw; i++)
    {
        ba.insert(i*3, 0x20);
    }

    ba.insert(3, "Tx_");
    ba.insert(18, " _");
    if (l < 8)
        ba.remove(20+3*l, 3*(8-l));
    ba.remove(0, 3);

    bd.append(date.currentDateTime().toString("dd.MM.yyyy hh:mm:ss.zzz"));
    bd.append("          ");
    bd.append(ba);
//        bd.append("\r");

    emit signal_showData(bd);
    emit signal_writeLog(bd);
}





//-----------------------------------------------------------------------------------//
//ѕереводим данные в видимый hex формат

/*QByteArray*/
void TCP_Client::make_hex_log_data(QByteArray data)
{
    QByteArray ba, bd;
    quint8 l, lenw;
    QDateTime date;

    while ((data.length() / 13) > 0)
    {
        bd.clear();
        // аждый пакет составл€ет 13 байт / делим на блоки по 13 байт
        ba = data.left(13).toHex();        

        bd.append(data.left(5));
        bd.remove(0,1);

        uint8_t idb[4];
        idb[0] = data.at(1);
        idb[1] = data.at(2);
        idb[2] = data.at(3);
        idb[3] = data.at(4);

        uint32_t idd = ((uint32_t)(idb[0]) << 24) | ((uint32_t)(idb[1]) << 16) | ((uint16_t)(idb[2]) << 8) | idb[3];
        qDebug() << idb[0] << idb[1] << idb[2] << idb[3] << idd;
        if (idd == 0x774)
        {
            decryptDt.clear();
            decryptDt.append(data.mid(5, 8));
        }
        else if (idd == 0x775)
        {
            decryptDt.append(data.mid(5, 8));
            emit signal_showPlainText(decryptDt);
        }
        else if (idd == 0x776)
        {
            decryptDt.clear();
            decryptDt.append(data.mid(5, 8));

//            decrDt[0] = data.at(5);
//            decrDt[1] = data.at(6);
//            decrDt[2] = data.at(7);
//            decrDt[3] = data.at(8);
//            decrDt[4] = data.at(9);
//            decrDt[5] = data.at(10);
//            decrDt[6] = data.at(11);
//            decrDt[7] = data.at(12);
        }
        else if (idd == 0x777)
        {
            decryptDt.append(data.mid(5, 8));

//            decrDt[8] = data.at(5);
//            decrDt[9] = data.at(6);
//            decrDt[10] = data.at(7);
//            decrDt[11] = data.at(8);
//            decrDt[12] = data.at(9);
//            decrDt[13] = data.at(10);
//            decrDt[14] = data.at(11);
//            decrDt[15] = data.at(12);

//            qDebug() << decrDt[0] << decrDt[1] << decrDt[2] << decrDt[3] << decrDt[4] << decrDt[5] << decrDt[6] << decrDt[7] << decrDt[8] << decrDt[9] << decrDt[10] << decrDt[11] << decrDt[12] << decrDt[13] << decrDt[14] << decrDt[15];

            emit signal_showDecrypt(decryptDt);
        }

        data.remove(0,13);
        bd.clear();
    //    ba.append(data.toHex());

        l = (ba.left(2).toInt()) & 0x0F;
        lenw = ba.length();
        for (int i=0; i < lenw; i++)
        {
            ba.insert(i*3, 0x20);
        }


        ba.insert(3, "Rx_");
        ba.insert(18, " _");
        if (l < 8)
            ba.remove(20+3*l, 3*(8-l));
        ba.remove(0, 3);

        bd.append(date.currentDateTime().toString("dd.MM.yyyy hh:mm:ss.zzz"));
        bd.append("          ");
        bd.append(ba);
//        bd.append("\r");

        emit signal_showData(bd);
        emit signal_writeLog(bd);
//        emit signal_showDecrypt(decryptDt);
    }

//    return ba;
}







void TCP_Client::slot_t_send_to_server_timeout()
{
    emit signal_sendToServer();
}


//void TCP_Client::slot_t_connectedState_timeout()
//{
//    tcp_socket->disconnectFromHost();
//    t_connectedState->stop();
//    t_send_to_server->stop();
//}


