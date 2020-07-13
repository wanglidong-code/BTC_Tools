import org.bitcoinj.core.*;
import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;


/**
 * @author 王立东
 * 给定压缩wif格式私钥,计算私钥的各种格式、对应公钥、对应地址
 * 可以通过ECKey的api,通过私钥计算公钥、地址,也可以使用如下代码中的方法。
 * 通过这些方法更容易和《精通比特币》中的格式做对比
 * 计算的结果在https://iancoleman.io/bitcoin-key-compression/进行对比
 */

public class BtcKeyTools {

    private final static String PRIVATE_KEY = "KwLqGuP8AfXRVSQcLkRQMgRGkARRCSSuHioVSeFpoaa2G2qo5jqZ";

    public static void main(String[] argsv) throws Exception {
        print_key_info(PRIVATE_KEY);
    }

    private static void print_key_info(String private_key) throws NoSuchAlgorithmException {
        System.out.println("输入的待分析私钥(压缩wif格式)为:" + private_key);
        NetworkParameters params = MainNetParams.get();
        DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(params, private_key);
        ECKey key = dumpedPrivateKey.getKey();
        System.out.println("----------------私钥解析开始---------------------");
        System.out.println("私钥256位数的Raw Binary为:" + key.getPrivKey());
        System.out.println("私钥256位数的对应的16进制格式:" + key.getPrivateKeyAsHex());
        System.out.println("私钥的wif格式(压缩):" + key.getPrivateKeyAsWiF(params));
        System.out.println("私钥的wif格式(非压缩): " + getUncompressBase58(key.getPrivateKeyAsHex()));
        System.out.println("私钥的wif压缩格式: " + getCompressBase58(key.getPrivateKeyAsHex()));

        System.out.println("----------------私钥解析结束,下面是公钥---------------");
        String compress_public_key = key.getPublicKeyAsHex();
        System.out.println("对应公钥压缩16进制格式:" + compress_public_key);
        //通过decompress函数获取不压缩的格式,也可以通过key_uncompress获取私钥的不压缩格式
        ECKey key_uncompress = key.decompress();
        String uncompress_public_key = key_uncompress.getPublicKeyAsHex();
        System.out.println("对应公钥不压缩16进制格式:" + uncompress_public_key);
        System.out.println("对应公钥X坐标:" + key_uncompress.getPubKeyPoint().getRawXCoord().toString());
        System.out.println("对应公钥Y坐标:" + key_uncompress.getPubKeyPoint().getRawYCoord().toString());

        System.out.println("----------------公钥解析结束,下面是地址---------------");
        System.out.println("API直接获取对应地址压缩16进制格式: " + LegacyAddress.fromKey(params, key).toString());
        System.out.println("API直接获取对应地址不压缩16进制格式:" + LegacyAddress.fromKey(params, key_uncompress).toString());
        System.out.println("算法通过公钥计算对应地址压缩16进制格式: " + getAddressByPublicKey(key.getPublicKeyAsHex()));
        System.out.println("算法通过公钥计算对应地址不压缩16进制格式:" + getAddressByPublicKey(key_uncompress.getPublicKeyAsHex()));

    }


    private static String getUncompressBase58(String hex_private_key) {
        //1.在16进制私钥前面加上0x80版本号
        String hex = "80" + hex_private_key;
        //2.对第1步结果进行SHA256哈希计算
        byte[] hash1 = Sha256Hash.hash(Hex.decode(hex));
        //3.将第2步结果进行SHA256哈希计算
        byte[] hash2 = Sha256Hash.hash(hash1);
        //4.取第3步结果的前4字节，加到第1步结果的末尾
        String result = hex + Hex.toHexString(hash2).substring(0, 8);
        //5.对第4步结果进行Base58编码
        return Base58.encode(Hex.decode(result));
    }

    private static String getCompressBase58(String hex_private_key) {
        //1.在16进制私钥前面加上0x80版本号,后面再加0x01
        String hex = "80" + hex_private_key + "01";
        //2.对第1步结果进行SHA256哈希计算
        byte[] hash1 = Sha256Hash.hash(Hex.decode(hex));
        //3.将第2步结果进行SHA256哈希计算
        byte[] hash2 = Sha256Hash.hash(hash1);
        //4.取第3步结果的前4字节，加到第1步结果的末尾
        String result = hex + Hex.toHexString(hash2).substring(0, 8);
        //5.对第4步结果进行Base58编码
        return Base58.encode(Hex.decode(result));
    }


    private static String getAddressByPublicKey(String public_key) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        //1.对公钥做SHA256
        byte[] s1 = null;
        MessageDigest sha = null;
        sha = MessageDigest.getInstance("SHA-256");
        s1 = sha.digest(Hex.decode(public_key));
        //2.SHA256摘要之后做RIPEMD-160
        byte[] r1 = null;
        MessageDigest rmd = MessageDigest.getInstance("RipeMD160");
        if (rmd == null || s1 == null) {
            System.out.println("can't get ripemd160 or sha result is null");
        }
        r1 = rmd.digest(s1);
        //3.在16进制结果前面加上0x00版本号(加上前缀之后做两次SHA256)
        String hex = "00"+Hex.toHexString(r1);
        //4.对结果进行SHA256哈希计算
        byte[] hash1 = Sha256Hash.hash(Hex.decode(hex));
        //5.将结果进行SHA256哈希计算
        byte[] hash2 = Sha256Hash.hash(hash1);
        //6.取第5步结果的前4字节，加到第3步结果的末尾
        String result = hex + Hex.toHexString(hash2).substring(0, 8);
        //5.对第4步结果进行Base58编码
        return Base58.encode(Hex.decode(result));
    }


}