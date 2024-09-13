package marnix.eddsa_keyspec_bc_fips;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

class EdDSAKeySpecTest {
	
	private static Provider jvmSunECProvider = Security.getProvider("SunEC");

	@Test
	void SucceedWithSunECOnly() throws Throwable {
		// use the standard JDK list of security providers, repairing from an earlier test if needed
		Security.removeProvider("BCFIPS");
		if (Security.getProvider("SunEC") == null) {
			Security.addProvider(jvmSunECProvider);
		}
		doScenario();
	}

	@Test
	void succeedWithBCFIPSandSunEC() throws Throwable {
		// use BCFIPS...
		Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
		// ...and the standard list of security providers, repairing from an earlier test if needed
		if (Security.getProvider("SunEC") == null) {
			Security.addProvider(jvmSunECProvider);
		}
		doScenario();
	}

	@Test
	void failWithBCFIPSOnly() throws Throwable {
		// make sure only the bc-fips.jar EdDSA implementation is available
		Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
		Security.removeProvider("SunEC");
		doScenario();
	}

	private void doScenario() throws NoSuchAlgorithmException, InvalidKeySpecException {
		// prepare the Java 15+ keyspec

		// Example coordinates for an Ed25519 public key point
		// The X coordinate is a byte array; EdDSA only uses the X coordinate.
		byte[] x = new byte[] { 0x7f, (byte) 0xb2, (byte) 0x9f, 0x19, (byte) 0x4f, 0x6c, (byte) 0x80, 0x6d, 0x12, 0x50,
				0x0f, (byte) 0xce, 0x08, (byte) 0xba, (byte) 0xa8, 0x35, 0x71, 0x52, (byte) 0xee, (byte) 0xe4, 0x42,
				0x3a, 0x3c, 0x46, 0x4c, 0x5b, 0x3b, (byte) 0xc4, 0x7a, (byte) 0xf4, 0x26 };
		EdECPoint point = new EdECPoint(true, new BigInteger(x));
		EdECPublicKeySpec publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, point);

		// use the keyspec

		KeyFactory keyFactory = KeyFactory.getInstance("EdDSA");
		keyFactory.generatePublic(publicKeySpec); // ignore the result, for this test case...
	}
}
