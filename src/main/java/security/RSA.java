package security;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.util.Random;

public class RSA {
	
	private static BigInteger n;
	private static BigInteger e;
	private static BigInteger d;
	
	public void keyGen(int keyLength) throws IOException{
		
		FileOutputStream fospub = new FileOutputStream("pub.key");
		FileOutputStream fospri = new FileOutputStream("pri.key");
		
		ObjectOutputStream objOutPub = new ObjectOutputStream(fospub);
		ObjectOutputStream objOutPri = new ObjectOutputStream(fospri);
		
		
		Random rnd = new Random();
		BigInteger p = BigInteger.probablePrime(keyLength,rnd);
		BigInteger q = p.nextProbablePrime();
		n = p.multiply(q);
		System.out.println("n " + n);
		//(p-1) x (q-1)
		BigInteger tn = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		
		
		//get e, should be relative prime to tn : gcd(tn, e) != 1
		Random rnd1 = new Random();
		
		e = BigInteger.probablePrime(tn.bitLength()-1, rnd1);
		if(!tn.gcd(e).equals(BigInteger.ONE)){
			System.out.println("tn and e's are not relative prime");
			while(!tn.gcd(e).equals(BigInteger.ONE)){
				e = BigInteger.probablePrime(tn.bitLength()-1, rnd1);
			}
		}
		
		//get d : inverse of e (mod tn)
		d = e.modInverse(tn);
		
		System.out.println("Writing public key and private key to the files");
		
		//public key
		objOutPub.writeObject(e);
		objOutPub.writeObject(n);
		
		//private key
		objOutPri.writeObject(d);
		objOutPri.writeObject(n);
		
		objOutPub.close();
		objOutPri.close();
		fospub.close();
		fospri.close();
		
		System.out.println("Completed!");
	}
	public static BigInteger encrypt(BigInteger p){
		return p.modPow(e, n);
		
	}
	public static BigInteger decrypt(BigInteger c){
		return c.modPow(d, n);
	}
	
	public static void main(String argv[]) throws IOException{
		RSA rsa = new RSA();
		rsa.keyGen(512);
		
		BigInteger plaintext = new BigInteger("25");
		BigInteger ciphertext;
		ciphertext = rsa.encrypt(plaintext);
		System.out.println("ciphertext: " + ciphertext);
		System.out.println("plaintext: " + rsa.decrypt(ciphertext));
		
	}

}
