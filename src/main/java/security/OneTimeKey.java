package security;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

public class OneTimeKey {

	public static byte[] newKey(Random r, int n) {
		byte[] rBytes = new byte[n];
		r.nextBytes(rBytes);
		return rBytes;
	}

	public static byte[] newKey(int n) {
		Random r = new Random(System.currentTimeMillis());
		return newKey(r, n);
	}

	public static byte[] xor(byte[] m, byte[] k) {
		byte[] encodedM = new byte[k.length];
		for (int i = 0; i < k.length; i++) {
			encodedM[i] = (byte) (m[i] ^ k[i]);
		}
		return encodedM;
	}

	public static void printKey(byte[] b, OutputStream os) throws IOException {
		byte[] k = newKey(b.length);
		os.write(xor(b, k));
	}

	public static void main(String argv[]) throws Exception {
		if (argv.length != 2) {
			System.out.println("java security.OneTimeKey <key>  <text> [ <text> ... ]");
		} else {
			System.out.println("original text is " + argv[1]);
			byte[] encodedM = xor(argv[1].getBytes(), argv[0].getBytes());
			System.out.println("encoded to " + new String(encodedM));
			byte[] decodedM = xor(encodedM, argv[0].getBytes());
			System.out.println("decoded to " + new String(decodedM));
		}
	}

}
