#include <QString>
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QFileDialog>
#include <QApplication>
#include <QMainWindow>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QPushButton>
#include <QStack>
#include <QMap>

#include <bits/stringfwd.h>
#include <array>
#include <unordered_map>
#include <memory>
#include <stdexcept>


#include "build.h"


#include "asn1/asn1_obj.h"
#include "asn1/der_enc.h"
#include "asn1/ber_dec.h"
#include "asn1/oids.h"

#include "base/botan.h"
#include "base/buf_comp.h"
#include "base/lookup.h"
#include "base/symkey.h"
#include "base/init.h"
#include "base/scan_name.h"
#include "base/secmem.h"
#include "base/sym_algo.h"

#include "block/block_cipher.h"
#include "block/aes/aes.h"
#include "block/aria/aria.h"
#include "block/blowfish/blowfish.h"
#include "block/camellia/camellia.h"
#include "block/cast128/cast128.h"
#include "block/cast128/cast_sboxes.h"
#include "block/cast256/cast256.h"
#include "block/cascade/cascade.h"
#include "block/des/des.h"
#include "block/des/desx.h"
#include "block/gost_28147/gost_28147.h"
#include "block/idea/idea.h"
#include "block/kasumi/kasumi.h"
#include "block/lion/lion.h"
#include "block/misty1/misty1.h"
#include "block/noekeon/noekeon.h"
#include "block/seed/seed.h"
#include "block/serpent/serpent.h"
#include "block/serpent/serpent_sbox.h"
#include "block/shacal2/shacal2.h"
#include "block/sm4/sm4.h"
#include "block/twofish/twofish.h"
#include "block/threefish_512/threefish_512.h"
#include "block/xtea/xtea.h"


#include "codec/hex/hex.h"
#include "codec/base64/base64.h"
#include "entropy/entropy_src.h"

#include "filters/filters.h"
#include "filters/data_snk.h"
#include "filters/filter.h"
#include "filters/pipe.h"
#include "filters/out_buf.h"
#include "filters/secqueue.h"

#include "hash/hash.h"
#include "hash/checksum/adler32/adler32.h"
#include "hash/checksum/crc24/crc24.h"
#include "hash/checksum/crc32/crc32.h"
#include "hash/gost_3411/gost_3411.h"
#include "hash/keccak/keccak.h"
#include "hash/md4/md4.h"
#include "hash/mdx_hash/mdx_hash.h"
#include "hash/md5/md5.h"
#include "hash/rmd160/rmd160.h"
#include "hash/sha1/sha160.h"
#include "hash/sha2_32/sha2_32.h"
#include "hash/sha2_64/sha2_64.h"
#include "hash/sha3/sha3.h"

#include "kdf/kdf.h"
#include "kdf/hkdf/hkdf.h"
#include "kdf/kdf1/kdf1.h"
#include "kdf/kdf2/kdf2.h"
#include "kdf/kdf1_iso18033/kdf1_iso18033.h"
#include "kdf/prf_tls/prf_tls.h"
#include "kdf/prf_x942/prf_x942.h"
#include "kdf/sp800_108/sp800_108.h"
#include "kdf/sp800_56a/sp800_56a.h"
#include "kdf/sp800_56c/sp800_56c.h"

#include "mac/mac.h"
#include "mac/cbc_mac/cbc_mac.h"
#include "mac/cmac/cmac.h"
#include "mac/gmac/gmac.h"
#include "mac/hmac/hmac.h"
#include "mac/poly1305/poly1305.h"
#include "mac/siphash/siphash.h"
#include "mac/x919_mac/x919_mac.h"

#include "math/bigint/bigint.h"
#include "math/bigint/divide.h"
#include "math/mp/mp_core.h"
#include "math/mp/mp_asmi.h"
#include "math/mp/mp_madd.h"
#include "math/numbertheory/monty.h"
#include "math/numbertheory/monty_exp.h"
#include "math/numbertheory/numthry.h"
#include "math/numbertheory/primality.h"
#include "math/numbertheory/reducer.h"


#include "modes/cipher_mode.h"
#include "modes/stream_mode.h"
#include "modes/aead/aead.h"
#include "modes/aead/ccm/ccm.h"
#include "modes/aead/chacha20poly1305/chacha20poly1305.h"
#include "modes/aead/eax/eax.h"
#include "modes/aead/gcm/gcm.h"
#include "modes/aead/ocb/ocb.h"
#include "modes/aead/siv/siv.h"
#include "modes/cbc/cbc.h"
#include "modes/mode_pad/mode_pad.h"
#include "modes/cfb/cfb.h"
#include "modes/xts/xts.h"

#include "pbkdf/argon2/argon2.h"
#include "pbkdf/bcrypt_pbkdf/bcrypt_pbkdf.h"
#include "pbkdf/pbkdf.h"
#include "pbkdf/pbkdf1/pbkdf1.h"
#include "pbkdf/pbkdf2/pbkdf2.h"
#include "pbkdf/pgp_s2k/pgp_s2k.h"
#include "pbkdf/pwdhash.h"
#include "pbkdf/scrypt/scrypt.h"

#include "pubkey/blinding.h"
#include "pubkey/pk_algs.h"
#include "pubkey/pk_keys.h"
#include "pubkey/pk_ops.h"
#include "pubkey/pk_ops_impl.h"
#include "pubkey/pk_ops_fwd.h"
#include "pubkey/pkcs8.h"
#include "pubkey/pubkey.h"
#include "pubkey/workfactor.h"
#include "pubkey/x509_key.h"

#include "pubkey/curve25519/curve25519.h"
#include "pubkey/dh/dh.h"
#include "pubkey/dsa/dsa.h"
#include "pubkey/dl_algo/dl_algo.h"
#include "pubkey/dl_group/dl_group.h"
#include "pubkey/ec_group/ec_group.h"
#include "pubkey/ec_group/point_gfp.h"
#include "pubkey/ec_group/point_mul.h"
#include "pubkey/ecc_key/ecc_key.h"
#include "pubkey/ecdh/ecdh.h"
#include "pubkey/ecdsa/ecdsa.h"
#include "pubkey/ecgdsa/ecgdsa.h"
#include "pubkey/eckcdsa/eckcdsa.h"
#include "pubkey/ed25519/ed25519.h"
#include "pubkey/ed25519/ed25519_internal.h"
#include "pubkey/ed25519/ed25519_fe.h"
#include "pubkey/elgamal/elgamal.h"
#include "pubkey/gost_3410/gost_3410.h"
#include "pubkey/keypair/keypair.h"
#include "pubkey/mce/code_based_util.h"
#include "pubkey/mce/gf2m_small_m.h"
#include "pubkey/mce/mce_internal.h"
#include "pubkey/mce/mceliece.h"
#include "pubkey/mce/polyn_gf2m.h"
#include "pubkey/pbes2/pbes2.h"
#include "pubkey/pem/pem.h"
#include "pubkey/rfc6979/rfc6979.h"
#include "pubkey/rsa/rsa.h"
#include "pubkey/sm2/sm2.h"
#include "pubkey/xmss/xmss.h"
#include "pubkey/xmss/xmss_hash.h"
#include "pubkey/xmss/xmss_parameters.h"
#include "pubkey/xmss/xmss_wots.h"

#include "pk_pad/eme.h"
#include "pk_pad/emsa.h"
#include "pk_pad/padding.h"
#include "pk_pad/eme_oaep/oaep.h"
#include "pk_pad/eme_pkcs1/eme_pkcs.h"
#include "pk_pad/eme_raw/eme_raw.h"
#include "pk_pad/emsa1/emsa1.h"
#include "pk_pad/emsa_x931/emsa_x931.h"
#include "pk_pad/emsa_pkcs1/emsa_pkcs1.h"
#include "pk_pad/emsa_pssr/pssr.h"
#include "pk_pad/emsa_raw/emsa_raw.h"
#include "pk_pad/hash_id/hash_id.h"
#include "pk_pad/iso9796/iso9796.h"
#include "pk_pad/mgf1/mgf1.h"

#include "rng/rng.h"
#include "rng/auto_rng/auto_rng.h"
#include "rng/hmac_drbg/hmac_drbg.h"
#include "rng/stateful_rng/stateful_rng.h"
#include "rng/system_rng/system_rng.h"

#include "stream/stream_cipher.h"
#include "stream/ctr/ctr.h"
#include "stream/ofb/ofb.h"
#include "stream/rc4/rc4.h"
#include "stream/chacha/chacha.h"
#include "stream/salsa20/salsa20.h"
#include "stream/shake_cipher/shake_cipher.h"

#include "utils/assert.h"
#include "utils/bswap.h"
#include "utils/bit_ops.h"
#include "utils/charset.h"
#include "utils/compiler.h"
#include "utils/cpuid/cpuid.h"
#include "utils/ct_utils.h"
#include "utils/codec_base.h"
#include "utils/donna128.h"
#include "utils/data_src.h"
#include "utils/exceptn.h"
#include "utils/ghash/ghash.h"
#include "utils/loadstor.h"
#include "utils/locking_allocator/locking_allocator.h"
#include "utils/mem_ops.h"
#include "utils/mem_pool/mem_pool.h"
#include "utils/mul128.h"
#include "utils/mutex.h"
#include "utils/os_utils.h"
#include "utils/parsing.h"
#include "utils/poly_dbl/poly_dbl.h"
#include "utils/rotate.h"
#include "utils/rounding.h"
#include "utils/safeint.h"
#include "utils/stl_util.h"
#include "utils/thread_utils/thread_pool.h"
#include "utils/timer.h"
#include "utils/types.h"
#include "utils/version.h"


const QString SRC="/home/zhouyu/develop/qt-repo/LBotan2.17/";
const QString dinclude="#include <botan";
const QString definedinclude="   #include <botan";


void changeFile(const QString &pattern,const QString& path,const QStringList& hcs){
    QFile readFile(path);
    bool isOK=readFile.open(QIODevice::ReadOnly|QIODevice::Text);
    QStringList lines;
    if(isOK){
        while (!readFile.atEnd()) {
            QByteArray line=readFile.readLine();
            QString ls(line);
            lines.append(ls);
        }
    }
    readFile.close();

    QFile writeFile(path);
    bool wisOK=writeFile.open(QIODevice::ReadWrite|QIODevice::Text);
    if(wisOK){
        QTextStream out(&writeFile);
        for (int i=0, len=lines.size();i<len ;i++ ) {
            QString line=lines.at(i);
            if(line.startsWith(pattern)){
                line="//"+line;

                QString suffix=line.mid(line.lastIndexOf("/")+1);
                suffix=suffix.mid(0,suffix.length()-2);
                qDebug()<<suffix;

                for (int j=0,len=hcs.size();j<len ;j++ ) {
                    QString sf=hcs.at(j);
                    QString sff=sf.mid(sf.lastIndexOf("/")+1);
                    if(sff==suffix){
                        qDebug()<<sff;
                        qDebug()<<sf;
                        QString fullsuffix=sf.mid(SRC.length());
                        qDebug()<<fullsuffix;
                        line.append("#include \"").append(fullsuffix).append("\"\n");
                        qDebug()<<line;
                    }

                }

            }
            out<<line;
        }
        writeFile.close();

    }
}

QStringList getFileList(const QString& sPath){
    QStringList hcs;
    QDir dir(sPath );
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks | QDir::Dirs | QDir::NoDotAndDotDot);
    dir.setSorting(QDir::Time | QDir::Reversed);
    QFileInfoList fileInfoList = dir.entryInfoList();
    foreach (QFileInfo fileInfo, fileInfoList) {
        if (fileInfo.isDir()) {
            hcs.append(getFileList(fileInfo.filePath()));

        } else {
            if(fileInfo.absoluteFilePath().endsWith(".h")||fileInfo.absoluteFilePath().endsWith(".cpp")){
                hcs.append(fileInfo.absoluteFilePath());
            }
        }

    }
    return hcs;
}
QStringList getDirs(const QString& sPath){
    QStringList hcs;
    QDir dir(sPath );
    dir.setFilter(QDir::Files | QDir::Hidden | QDir::NoSymLinks | QDir::Dirs | QDir::NoDotAndDotDot);
    dir.setSorting(QDir::Time | QDir::Reversed);
    QFileInfoList fileInfoList = dir.entryInfoList();
    foreach (QFileInfo fileInfo, fileInfoList) {
        if (fileInfo.isDir()) {
            hcs.append(fileInfo.filePath());
            hcs.append(getDirs(fileInfo.filePath()));
        }

    }
    return hcs;
}


void deleteFile(const QString &filename){
    QStringList hcs=    getDirs(SRC);
    for (int i=0,len=hcs.size();i<len ;i++ ) {
        QString dir=hcs.at(i);
        qDebug()<<dir;
        QFile tmp(dir+"/"+filename);

        if(tmp.exists()){
            tmp.remove();
        }
    }
}

void change(const QString &pattern){
    qDebug("change");

    QStringList files=getFileList(SRC);
    for (int i=0,len=files.size();i<len ;i++ ) {
        QString file=files.at(i);
        changeFile(pattern,file,files);

    }
}

void findInFile(const QString& fc){
    QStringList hcs=getFileList(SRC);

    for (int i=0, len=hcs.size();i<len ;i++ ) {
        QString hc=hcs.at(i);
        QFile readFile(hc);
        bool isOK=readFile.open(QIODevice::ReadOnly|QIODevice::Text);
        if(isOK){
            while (!readFile.atEnd()) {
                QByteArray line=readFile.readLine();
                QString ls(line);
                if(ls.contains(fc)){
                    qDebug()<<hc;
                }
            }
        }

    }

}
void findFile(const QString& fc){
    QStringList hcs=getFileList(SRC);
    for (int i=0, len=hcs.size();i<len ;i++ ) {
        QString hc=hcs.at(i);
        if(hc.contains(fc)){
            qDebug()<<hc;
        }
    }
}
void remark(){

    //    prov/commoncrypto/commoncrypto.h
    //    prov/commoncrypto/commoncrypto_utils.cpp
    //    prov/commoncrypto/commoncrypto_mode.cpp
    //    prov/commoncrypto/commoncrypto_hash.cpp
    //    prov/commoncrypto/commoncrypto_block.cpp
    //    prov/commoncrypto/commoncrypto_block.cpp
    //    modes/cipher_mode.cpp
    //    block/block_cipher.cpp
    //    hash/hash.cpp

    //    .pro do not
    //    entropy/win32_stats/es_win32.cpp
    //    prov/commoncrypto
    //    prov/tpm/tpm.h

    //    pubkey/xmss/xmss_address.h
    //    tls/tls_messages.h
    //    tls/tls_seq_numbers.h
    //    utils/filesystem.h
    //    utils/ct_utils.h
    //    #include <valgrind/memcheck.h>
    //    utils/simd/simd_32.h
    //    utils/simd/simd_avx2/simd_avx2.h
    //    #include <tss/tspi.h>

    //    entropy/entropy_srcs.cpp
    //    -#include <botan/internal/rdrand.h>
    //    -#include <botan/internal/rdseed.h>
    //    #include <botan/internal/p9_darn.h>
    //    #include <botan/internal/dev_random.h>
    //    #include <botan/internal/es_win32.h>
    //    #include <botan/internal/proc_walk.h>
    //    #include <botan/internal/os_utils.h>
    //    #include <botan/internal/getentropy.h>

}
void test(){
    //     std::string m_key="";
    //      std::string m_iv="";
    //    Botan::SymmetricKey key(
    //                reinterpret_cast<const Botan::byte *>(m_key.data()),
    //                m_key.size());

    //    Botan::InitializationVector iv(
    //                reinterpret_cast<const Botan::byte *>(m_iv.data()),
    //                m_iv.size());
    //    std::string  al="AES-128/CBC";
    //     Botan::Keyed_Filter *filter = Botan::get_cipher("AES-128",
    //                  Botan::Cipher_Dir::ENCRYPTION );

    //     std::unique_ptr<Botan::Pipe> pipe = std::make_unique<Botan::Pipe>(filter);
    //    Botan::Pipe pipe(new Botan::Base64_Encoder ,Botan::get_cipher("",Botan::ENCRYPTION));

    //Botan::hex_encode(
    //    // The algorithm we want is specified by a string
    //      std::string m_key="";
    //      std::string m_iv="";
    //    Botan::SymmetricKey key(
    //                reinterpret_cast<const Botan::byte *>(m_key.data()),
    //                m_key.size());

    //    Botan::InitializationVector iv(
    //                reinterpret_cast<const Botan::byte *>(m_iv.data()),
    //                m_iv.size());
    //    std::string  al="AES-128/CBC";
    //     Botan::Keyed_Filter *filter = Botan::get_cipher("AES-128/CBC/PKCS5",
    //                  Botan::Cipher_Dir::ENCRYPTION );

    //     std::unique_ptr<Botan::Pipe> pipe = std::make_unique<Botan::Pipe>(filter);
    //    Botan::Pipe pipe(new Botan::Base64_Encoder ,Botan::get_cipher("",Botan::ENCRYPTION));

    //pipe->process_msg(
    //    Botan::Pipe pipe(Botan::get_cipher("AES-128/CBC", key, iv, Botan::ENCRYPTION));
}


void initUI(){
    QMainWindow *window=new QMainWindow();
    if (window->objectName().isEmpty())
        window->setObjectName(QString::fromUtf8("MainWindow"));
    window->resize(400, 600);
    QWidget *centralwidget = new QWidget(window);
    centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
    QWidget *upWidget = new QWidget(centralwidget);
    upWidget->setObjectName(QString::fromUtf8("upLayoutWidget"));

    QGridLayout *upLayout = new QGridLayout(upWidget);
    //    upLayout->setColumnStretch(0,1);
    //    upLayout->setColumnStretch(1,3);
    //    upLayout->setSpacing(10);
    upLayout->setObjectName(QString::fromUtf8("verticalLayout"));
    //    upLayout->setSizeConstraint(QLayout::SetDefaultConstraint);
    //    upLayout->setContentsMargins(10, 20, 10, 10);

    QLabel*usernameLabel= new QLabel("username");
    upLayout->addWidget(usernameLabel,0,0);
    QLineEdit *usernameLine = new QLineEdit(upWidget);
    usernameLine->setObjectName(QString::fromUtf8("username"));
    usernameLine->setEnabled(true);
    //    usernameLine->setBaseSize(QSize(200, 20));
    upLayout->addWidget(usernameLine,0,1);

    QLabel *passwordLabel= new QLabel("password");
    upLayout->addWidget(passwordLabel,1,0);
    QLineEdit *passwordLine = new QLineEdit(upWidget);
    passwordLine->setObjectName(QString::fromUtf8("password"));
    upLayout->addWidget(passwordLine,1,1);

    //graphics
    QWidget *graphicsWidget=new QWidget(centralwidget);
    graphicsWidget->setGeometry(QRect(10,100,300,200));//293,190
    QPalette graphicsWidgetPalette=graphicsWidget->palette();
    graphicsWidgetPalette.setBrush(QPalette::Background,Qt::GlobalColor::gray);
    graphicsWidget->setPalette(graphicsWidgetPalette);
    QGridLayout *graphicsLayout=new QGridLayout(graphicsWidget);
    graphicsLayout->setMargin(0);
    graphicsLayout->setSpacing(0);
    graphicsLayout->setHorizontalSpacing(0);
    graphicsLayout->setVerticalSpacing(0);
    QGraphicsView *graphicsView = new QGraphicsView(graphicsWidget);
    graphicsView->setObjectName(QString::fromUtf8("captcha"));
    graphicsLayout->addWidget(graphicsView,0,0);

    //refresh
    QWidget *refreshWidget=new QWidget(centralwidget);
    //    refreshWidget->setStyleSheet("border:1px solid blue;");
    QPushButton *refreshButton=new QPushButton("刷新");
    refreshButton->setCursor(Qt::PointingHandCursor);
    refreshButton->setStyleSheet("border:none;");
    refreshWidget->setGeometry(QRect(270,100,30,30));
    QVBoxLayout *relayout=new QVBoxLayout(refreshWidget);
    relayout->setMargin(0);
    relayout->setSpacing(0);
    relayout->setAlignment(Qt::AlignmentFlag::AlignCenter);
    relayout->addWidget(refreshButton);

    //circle
    //    QLabel *label=new QLabel("");
    //    const QString lred = "min-width:28px;min-height:28px;max-width:28px;max-height:28px;border-radius:14px;background:red";
    //    label->setStyleSheet(lred);
    //    QWidget *lWidget=new QWidget(centralwidget);
    //    lWidget->setGeometry(QRect(270,170,28,28));
    //    QVBoxLayout *lrelayout=new QVBoxLayout(lWidget);
    //    lrelayout->setMargin(0);
    //    lrelayout->setSpacing(0);
    //    lrelayout->setAlignment(Qt::AlignmentFlag::AlignCenter);
    //    lrelayout->addWidget(label);

    QStack<QWidget*> *stackWidgets=new QStack<QWidget*>();
    QStack<QWidget*>*remainStackWidgets=new QStack<QWidget*>();
    //    map=new QMap<QWidget*,Pos*>();
    for(int i=0;i<8;i++){
        QWidget *widget=new QWidget(centralwidget);
        stackWidgets->push(widget);
    }

    QWidget *submitWidget=new QWidget(centralwidget);
    submitWidget->setGeometry(QRect(10,300,300,60));
    QHBoxLayout *slayout=new QHBoxLayout(submitWidget);
    QPushButton *submitButton = new QPushButton();
    submitButton->setObjectName(QString::fromUtf8("submit"));
    slayout->addWidget(submitButton);

    window->setCentralWidget(centralwidget);

    //    menubar = new QMenuBar(MainWindow);
    //    menubar->setObjectName(QString::fromUtf8("menubar"));
    //    menubar->setGeometry(QRect(0, 0, 712, 22));
    //    this->setMenuBar(menubar);
    //    statusbar = new QStatusBar(MainWindow);
    //    statusbar->setObjectName(QString::fromUtf8("statusbar"));
    //    this->setStatusBar(statusbar);

    window->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", nullptr));
    submitButton->setText(QApplication::translate("MainWindow", "login", nullptr));

    QMetaObject::connectSlotsByName(window);

    window->setMouseTracking(true);
    graphicsView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    graphicsView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    window->show();
}
int main(int arg,char*argv[]){
    QApplication app(arg,argv);

    //        change();
    //    change(definedinclude);
    //    findFile("rdrand.h");

//        initUI();

    return app.exec();
}
