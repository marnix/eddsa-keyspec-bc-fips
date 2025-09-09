package marnix.eddsa_keyspec_bc_fips;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.Test;

class EdDSAKeySpecTest {

	private static Provider jvmSunECProvider = Security.getProvider("SunEC");

	@Test
	void SucceedWithSunECOnly() throws Throwable {
		// use the standard JDK list of security providers, repairing from an earlier
		// test if needed
		Security.removeProvider("BCFIPS");
		if (Security.getProvider("SunEC") == null) {
			Security.addProvider(jvmSunECProvider);
		}
		doScenario();
	}

	@Test
	void succeedWithBCFIPSthenSunEC() throws Throwable {
		// use BCFIPS at the top...
		Security.removeProvider("BCFIPS");
		Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
		// ...and then the standard list of security providers, repairing from an
		// earlier test if needed
		if (Security.getProvider("SunEC") == null) {
			Security.addProvider(jvmSunECProvider);
		}
		doScenario();
	}

	/**
	 * This unit test fails as follows:
	 * 
	 * <pre>
	 * java.security.spec.InvalidKeySpecException: keySpec for PublicKey not recognized: java.security.spec.EdECPublicKeySpec
	 *         at org.bouncycastle.jcajce.provider.BaseKeyFactory.engineGeneratePublic(BaseKeyFactory.java:60)
	 *         at org.bouncycastle.jcajce.provider.ProvEdEC$KeyFactorySpi.engineGeneratePublic(ProvEdEC.java:374)
	 *         at java.base/java.security.KeyFactory.generatePublic(KeyFactory.java:351)
	 *         at marnix.eddsa_keyspec_bc_fips.EdDSAKeySpecTest.doScenario(EdDSAKeySpecTest.java:63)
	 *         at marnix.eddsa_keyspec_bc_fips.EdDSAKeySpecTest.failWithBCFIPSOnly(EdDSAKeySpecTest.java:46)
	 * </pre>
	 * 
	 * @throws Throwable
	 */
	@Test
	void failWithBCFIPSOnly() throws Throwable {
		// make sure only the bc-fips.jar EdDSA implementation is available
		Security.removeProvider("BCFIPS");
		Security.insertProviderAt(new BouncyCastleFipsProvider(), 1);
		Security.removeProvider("SunEC");
		doScenario();
	}

	private void doScenario() throws Throwable {
		// prepare the Java 15+ keyspec

		// Example coordinates for an Ed25519 public key point
		// The X coordinate is a byte array; EdDSA only uses the X coordinate.
		// In Ed25519, the public key is an 32 little-endian byte array:
		byte[] ed25519PublicKey  = new byte[] {
			    (byte)0x1A, (byte)0xD5, (byte)0x25, (byte)0x8F, (byte)0x60, (byte)0x2D, (byte)0x56, (byte)0xC9,
			    (byte)0xB2, (byte)0xA7, (byte)0x25, (byte)0x95, (byte)0x60, (byte)0xC7, (byte)0x2C, (byte)0x69,
			    (byte)0x5C, (byte)0xDC, (byte)0xD6, (byte)0xFD, (byte)0x31, (byte)0xE2, (byte)0xA4, (byte)0xC0,
			    (byte)0xFE, (byte)0x53, (byte)0x6E, (byte)0xCD, (byte)0xD3, (byte)0x36, (byte)0x69, (byte)0x21
			};

		EdECPoint point = new EdECPoint(true, new BigInteger(ed25519PublicKey));
		EdECPublicKeySpec publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, point);

		// use the keyspec

		KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
		keyFactory.generatePublic(publicKeySpec); // ignore the result, for this test case...

	
		// Example coordinates for an Ed448 public key point
		// The X coordinate is a byte array; EdDSA only uses the X coordinate.
		// In Ed448, the public key is an 57 little-endian byte array:
		byte[] ed448PublicKey = new byte[] {
			    (byte)0x00, (byte)0xa6, (byte)0x1d, (byte)0x3f, (byte)0x5e, (byte)0xbf, (byte)0xde, (byte)0x3c,
			    (byte)0xbf, (byte)0xd0, (byte)0x26, (byte)0xca, (byte)0xd5, (byte)0x4f, (byte)0x4c, (byte)0x4c,
			    (byte)0x7e, (byte)0x08, (byte)0x9e, (byte)0xc1, (byte)0x2a, (byte)0xd7, (byte)0x0c, (byte)0xaa,
			    (byte)0x82, (byte)0xd5, (byte)0x74, (byte)0x42, (byte)0x70, (byte)0x3d, (byte)0x99, (byte)0x37,
			    (byte)0xfa, (byte)0x70, (byte)0x79, (byte)0x1d, (byte)0x28, (byte)0x89, (byte)0xaa, (byte)0x13,
			    (byte)0x15, (byte)0x61, (byte)0x3d, (byte)0xac, (byte)0x75, (byte)0xca, (byte)0xa5, (byte)0x84,
			    (byte)0xc1, (byte)0x86, (byte)0xd0, (byte)0x15, (byte)0x62, (byte)0x3c, (byte)0x1e, (byte)0xbd,
			    (byte)0xa6
			};

		point = new EdECPoint(true, new BigInteger(ed448PublicKey));
		publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED448, point);

		// use the keyspec

		keyFactory = KeyFactory.getInstance("Ed448");
		keyFactory.generatePublic(publicKeySpec); // ignore the result, for this test case...	
	}
}
