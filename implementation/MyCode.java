package implementation;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.swing.JOptionPane;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import code.GuiException;
import gui.Constants;
import gui.GuiInterfaceV1;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

	private final String keystore_name = "keystore.p12";
	private final String password = "password";

	private KeyStore keystore;

	private PublicKey CSRPublicKey = null;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
	}

	@Override
	public boolean canSign(String keypair_name) {
		try {
			if (!keystore.containsAlias(keypair_name))
				return false;

			X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
			int isCA = cert.getBasicConstraints();

			if (isCA == -1)
				return false;
			else
				return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
		FileOutputStream fos = null;

		try {
			if (!keystore.containsAlias(keypair_name))
				return false;
			X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
			X509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
			PublicKey pu = cert.getPublicKey();
			PrivateKey pr = (PrivateKey) keystore.getKey(keypair_name, null);

			// Provera da li je vec potpisan
			if (!certHolder.getSubject().equals(certHolder.getIssuer())) {
				GuiInterfaceV1.reportError("Selected certificate is already signed!");
				return false;
			}

			PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(
					certHolder.getSubject(), pu);

			JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(algorithm).setProvider("BC");
			ContentSigner signer = signerBuilder.build(pr);
			PKCS10CertificationRequest request = requestBuilder.build(signer);

			fos = new FileOutputStream(file);
			fos.write(request.getEncoded());
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
		FileOutputStream fos = null;
		FileWriter fw = null;
		JcaPEMWriter writer = null;

		try {
			if (format == Constants.HEAD) {
				Certificate cert = keystore.getCertificate(keypair_name);

				if (encoding == Constants.DER) {
					fos = new FileOutputStream(file);
					fos.write(cert.getEncoded());
				}
				if (encoding == Constants.PEM) {
					fw = new FileWriter(file);
					writer = new JcaPEMWriter(fw);
					writer.writeObject(cert);
				}
			}
			if (format == Constants.CHAIN) {
				fw = new FileWriter(file);
				writer = new JcaPEMWriter(fw);

				if (keystore.isKeyEntry(keypair_name)) {
					Certificate[] chain = keystore.getCertificateChain(keypair_name);
					for (Certificate cert : chain)
						writer.writeObject(cert);
				}
				if (keystore.isCertificateEntry(keypair_name))
					writer.writeObject(keystore.getCertificate(keypair_name));
			}

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fos != null)
					fos.close();
				if (writer != null)
					writer.close();
				if (fw != null)
					fw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		FileOutputStream fos = null;

		try {
			fos = new FileOutputStream(file);

			KeyStore store = KeyStore.getInstance("PKCS12", "BC");
			store.load(null, null);

			Key key = keystore.getKey(keypair_name, null);
			Certificate[] chain = keystore.getCertificateChain(keypair_name);

			store.setKeyEntry(keypair_name, key, null, chain);
			store.store(fos, password.toCharArray());

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		try {
			if (!keystore.containsAlias(keypair_name))
				return null;
			X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
			return cert.getPublicKey().getAlgorithm();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		try {
			if (!keystore.containsAlias(keypair_name))
				return null;
			X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
			if (cert.getPublicKey() instanceof DSAPublicKey) {
				DSAPublicKey dsakey = (DSAPublicKey) cert.getPublicKey();
				return Integer.toString(dsakey.getParams().getP().bitLength());
			}
			if (cert.getPublicKey() instanceof BCRSAPublicKey) {
				BCRSAPublicKey rsakey = (BCRSAPublicKey) cert.getPublicKey();
				return Integer.toString(rsakey.getModulus().bitLength());
			}
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getSubjectInfo(String keypair_name) {
		try {
			if (!keystore.containsAlias(keypair_name))
				return null;

			X509CertificateHolder holder = new JcaX509CertificateHolder(
					(X509Certificate) keystore.getCertificate(keypair_name));

			return holder.getSubject().toString();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean importCAReply(String file, String keypair_name) {
		FileOutputStream fos = null;

		try {
			Path path = Paths.get(file);
			byte[] data = Files.readAllBytes(path);
			CMSSignedData signedData = new CMSSignedData(data);

			Store<X509CertificateHolder> certStore = signedData.getCertificates();
			Collection<X509CertificateHolder> certCollection = certStore.getMatches(null);

			Certificate[] chain = new Certificate[2];

			for (X509CertificateHolder holder : certCollection) {
				X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);

				if (cert.getBasicConstraints() == -1)
					chain[0] = cert;
				else
					chain[1] = cert;
			}

			X509CertificateHolder certHolder = new JcaX509CertificateHolder((X509Certificate) chain[0]);

			PrivateKey pr = (PrivateKey) keystore.getKey(keypair_name, null);
			PublicKey pu = chain[0].getPublicKey();

			X509Certificate selectedCert = (X509Certificate) keystore.getCertificate(keypair_name);
			X509CertificateHolder selectedCertHolder = new JcaX509CertificateHolder(selectedCert);

			// Provera da li je vec potpisan
			if (!selectedCertHolder.getSubject().equals(selectedCertHolder.getIssuer())) {
				GuiInterfaceV1.reportError("Selected certificate is already signed!");
				return false;
			}

			//Provera da li je PKCS7 odgovor namenjen selektovanom sertifikatu
			if (!pu.equals(selectedCert.getPublicKey())) {
				GuiInterfaceV1.reportError("PKCS7 file does not match the selected certificate!");
				return false;
			}

			keystore.deleteEntry(keypair_name);
			keystore.setKeyEntry(keypair_name, pr, null, chain);
			fos = new FileOutputStream(keystore_name);
			keystore.store(fos, password.toCharArray());

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public String importCSR(String file) {
		try {
			Path path = Paths.get(file);
			JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(Files.readAllBytes(path));
			CSRPublicKey = request.getPublicKey();

			return request.getSubject().toString();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) {
		FileInputStream fis = null;
		FileOutputStream fos = null;

		try {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
			fis = new FileInputStream(file);

			Certificate cert = certFactory.generateCertificate(fis);
			keystore.setCertificateEntry(keypair_name, cert);

			fos = new FileOutputStream("keystore.p12");
			keystore.store(fos, "password".toCharArray());

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fis != null)
					fis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		FileInputStream fis = null;
		FileOutputStream fos = null;

		try {
			fis = new FileInputStream(file);

			KeyStore store = KeyStore.getInstance("PKCS12", "BC");
			store.load(fis, password.toCharArray());

			Enumeration<String> aliases = store.aliases();

			if (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Key key = store.getKey(alias, password.toCharArray());
				Certificate[] chain = store.getCertificateChain(alias);
				keystore.setKeyEntry(keypair_name, key, null, chain);
			}
			fos = new FileOutputStream("keystore.p12");
			keystore.store(fos, "password".toCharArray());

			return true;
		} catch (Exception e) {
			if (e instanceof IOException)
				GuiInterfaceV1.reportError("Pogresan password");
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fis != null)
					fis.close();
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public int loadKeypair(String keypair_name) {

		try {
			if (keystore.containsAlias(keypair_name) == false)
				return -1;

			X509Certificate cert = (X509Certificate) keystore.getCertificate(keypair_name);
			X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());

			int version = 0;
			switch (cert.getVersion()) {
			case 3:
				version = Constants.V3;
				break;
			default:
				GuiInterfaceV1.reportError("Nije podrzana verzija sertifikata (samo v3)!");
				return -1;
			}

			access.setVersion(version);
			access.setSerialNumber(certHolder.getSerialNumber().toString());
			access.setNotBefore(certHolder.getNotBefore());
			access.setNotAfter(certHolder.getNotAfter());

			access.setPublicKeyAlgorithm(cert.getPublicKey().getAlgorithm());
			access.setPublicKeyDigestAlgorithm(cert.getSigAlgName().replace("WITH", "with"));

			if (cert.getPublicKey() instanceof DSAPublicKey) {
				DSAPublicKey dsakey = (DSAPublicKey) cert.getPublicKey();
				access.setPublicKeyParameter(Integer.toString(dsakey.getParams().getP().bitLength()));
			}
			if (cert.getPublicKey() instanceof BCRSAPublicKey) {
				BCRSAPublicKey rsakey = (BCRSAPublicKey) cert.getPublicKey();
				access.setPublicKeyParameter(Integer.toString(rsakey.getModulus().bitLength()));
			}

			X500Name subject = certHolder.getSubject();
			access.setSubject(subject.toString());
			access.setSubjectSignatureAlgorithm(cert.getPublicKey().getAlgorithm());

			X500Name issuer = certHolder.getIssuer();

			// ---------------------------EXTENSIONS-------------------------

			Extensions exts = certHolder.getExtensions();

			if (exts != null) {
				// ---------------------------EKU-------------------------

				ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(exts);
				if (eku != null) {
					boolean[] bool = new boolean[Constants.NUM_OF_EKU];
					if (eku.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage))
						bool[0] = true;
					if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth))
						bool[1] = true;
					if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth))
						bool[2] = true;
					if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning))
						bool[3] = true;
					if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection))
						bool[4] = true;
					if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping))
						bool[5] = true;
					if (eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning))
						bool[6] = true;

					access.setExtendedKeyUsage(bool);
					access.setCritical(Constants.EKU, certHolder.getExtension(Extension.extendedKeyUsage).isCritical());
				}
			}
			
			if (cert.getSubjectAlternativeNames() != null) {
				if (cert.getCriticalExtensionOIDs().contains(Extension.subjectAlternativeName.toString()))
					access.setCritical(Constants.SAN, true);
				else
					access.setCritical(Constants.SAN, false);
				Collection<List<?>> collNames = cert.getSubjectAlternativeNames();
				ArrayList<List<?>> arrNames = new ArrayList<>(collNames);
				StringBuilder altNames = new StringBuilder("");

				for (int i = 0; i < arrNames.size(); i++) {
					List<?> list = (List<?>) arrNames.get(i);
					switch (list.get(0).toString()) {
					case "0": {
						altNames.append("otherName=");
						ByteArrayInputStream inStr = new ByteArrayInputStream((byte[]) list.get(1));
						ASN1InputStream asnIS = new ASN1InputStream(inStr);
						ASN1Primitive derOn = asnIS.readObject();
						DLSequence dlSeq = (DLSequence) derOn;
						altNames.append(dlSeq.getObjectAt(0) + "=");
						inStr.close();
						asnIS.close();
						DERTaggedObject derObj = (DERTaggedObject) dlSeq.getObjectAt(1);
						derObj = (DERTaggedObject) derObj.getObject();
						altNames.append(derObj.getObject());
						break;
					}
					case "1":
						altNames.append("rfc822Name=");
						altNames.append(list.get(1).toString());
						break;
					case "2":
						altNames.append("dNSName=");
						altNames.append(list.get(1).toString());
						break;
					case "3":
						altNames.append("x400Address=");
						altNames.append(list.get(1).toString());
						break;
					case "4":
						altNames.append("directoryName=");
						altNames.append(list.get(1).toString());
						break;
					case "5":
						altNames.append("ediPartyName");
						break;
					case "6":
						altNames.append("uniformResourceIdentifier=");
						altNames.append(list.get(1).toString());
						break;
					case "7":
						altNames.append("iPAddress=");
						altNames.append(list.get(1).toString());
						break;
					case "8":
						altNames.append("registeredID=");
						altNames.append(list.get(1).toString());
						break;
					}
					if (i < arrNames.size() - 1)
						altNames.append(",");
				}
				access.setAlternativeName(Constants.SAN, altNames.toString());
			}
			// ---------------------------EXTENSIONS-------------------------

			if (keystore.isCertificateEntry(keypair_name)) {
				if (!subject.equals(issuer)) {
					access.setIssuer(issuer.toString());
					access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
				}
				return 2;
			}
			if (subject.equals(issuer)) {
				return 0;
			} else {
				access.setIssuer(issuer.toString());
				access.setIssuerSignatureAlgorithm(cert.getSigAlgName());
				return 1;
			}

		} catch (Exception e) {
			e.printStackTrace();
			return -1;
		}
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		FileInputStream fis = null;
		FileOutputStream fos = null;
		try {
			Security.addProvider(new BouncyCastleProvider());
			keystore = KeyStore.getInstance("PKCS12", "BC");

			try {
				fis = new FileInputStream("keystore.p12");
				keystore.load(fis, "password".toCharArray());
			} catch (FileNotFoundException f) {
				keystore.load(null, null);
				fos = new FileOutputStream("keystore.p12");
				keystore.store(fos, "password".toCharArray());
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (fis != null)
					fis.close();
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			return keystore.aliases();
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean removeKeypair(String keypair_name) {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(keystore_name);
			keystore.deleteEntry(keypair_name);
			keystore.store(fos, password.toCharArray());
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public void resetLocalKeystore() {
		FileOutputStream fos = null;
		try {
			keystore = KeyStore.getInstance("PKCS12", "BC");
			keystore.load(null, null);
			fos = new FileOutputStream("keystore.p12");
			keystore.store(fos, "password".toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public boolean saveKeypair(String keypair_name) {
		FileOutputStream fos = null;

		int version = access.getVersion();
		if (version != Constants.V3) {
			GuiInterfaceV1.reportError("Only version 3 is allowed!");
			return false;
		}
		if (!"DSA".equals(access.getPublicKeyAlgorithm())) {
			GuiInterfaceV1.reportError("Only DSA algorithm is allowed!");
			return false;
		}
		try {
			if (keystore.containsAlias(keypair_name)) {
				GuiInterfaceV1.reportError("Alias already exists!");
				return false;
			}
		} catch (KeyStoreException e1) {
			e1.printStackTrace();
			return false;
		}

		X500Name subject = new X500Name(access.getSubject());
		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();
		BigInteger serial = new BigInteger(access.getSerialNumber());
		String algorithm = access.getPublicKeyAlgorithm();
		int keyLength = Integer.parseInt(access.getPublicKeyParameter());
		String digest = access.getPublicKeyDigestAlgorithm();

		try {
			KeyPairGenerator keygen = KeyPairGenerator.getInstance(algorithm, "BC");
			keygen.initialize(keyLength);
			KeyPair keypair = keygen.generateKeyPair();
			PrivateKey pr = keypair.getPrivate();
			PublicKey pu = keypair.getPublic();

			X509v3CertificateBuilder gen = new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter,
					subject, pu);
			ContentSigner signer = new JcaContentSignerBuilder(digest).setProvider("BC").build(pr);

			// ---------------------------EXTENSIONS-------------------------

			// ---------------------------EKU-------------------------

			boolean[] usages = access.getExtendedKeyUsage();
			Vector<KeyPurposeId> vector = new Vector<>();
			for (int i = 0; i < Constants.NUM_OF_EKU; i++) {
				if (usages[i] == true) {
					switch (i) {
					case 0:
						vector.add(KeyPurposeId.anyExtendedKeyUsage);
						break;
					case 1:
						vector.add(KeyPurposeId.id_kp_serverAuth);
						break;
					case 2:
						vector.add(KeyPurposeId.id_kp_clientAuth);
						break;
					case 3:
						vector.add(KeyPurposeId.id_kp_codeSigning);
						break;
					case 4:
						vector.add(KeyPurposeId.id_kp_emailProtection);
						break;
					case 5:
						vector.add(KeyPurposeId.id_kp_timeStamping);
						break;
					case 6:
						vector.add(KeyPurposeId.id_kp_OCSPSigning);
						break;
					}
				}
			}

			if (!vector.isEmpty()) {
				@SuppressWarnings("deprecation")
				ExtendedKeyUsage ext3 = new ExtendedKeyUsage(vector);

				gen.addExtension(Extension.extendedKeyUsage, access.isCritical(Constants.EKU), ext3);
			}
			
			// SUBJECT ALTERNATIVE NAME

						String[] altNamesArr = access.getAlternativeName(Constants.SAN);
						if (altNamesArr.length > 0)
							try {
								GeneralName[] names = new GeneralName[altNamesArr.length];
								for (int i = 0; i < altNamesArr.length; i++) {
									if(altNamesArr[i].contains("dNSName="))
										names[i]= new GeneralName(GeneralName.dNSName, altNamesArr[i].substring(altNamesArr[i].indexOf("dNSName=")+8));
									else if (altNamesArr[i].contains("rfc822Name="))
										names[i] = new GeneralName(GeneralName.rfc822Name,altNamesArr[i].substring(altNamesArr[i].indexOf("rfc822Name=") + 11));
									else if (altNamesArr[i].contains("x400Address"))
										names[i] = new GeneralName(GeneralName.x400Address, new DERUTF8String(altNamesArr[i].substring(altNamesArr[i].indexOf("x400Address=") + 12)));
									else if (altNamesArr[i].contains("otherName=")) {

										String otherTypeOid = altNamesArr[i].substring(altNamesArr[i].indexOf("=") + 1,altNamesArr[i].lastIndexOf("="));
										ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
										String otherValue = altNamesArr[i].substring(altNamesArr[i].lastIndexOf("=") + 1);
										ASN1EncodableVector vectori = new ASN1EncodableVector();
										vectori.add(type);
										vectori.add(new DERTaggedObject(true, 0, new DERUTF8String(otherValue)));
										DERSequence seq = new DERSequence(vectori);
										names[i] = new GeneralName(GeneralName.otherName, seq);
									} else if (altNamesArr[i].contains("directoryName="))
										names[i] = new GeneralName(GeneralName.directoryName,altNamesArr[i].substring(altNamesArr[i].indexOf("directoryName=") + 14));
									else if (altNamesArr[i].contains("ediPartyName=")) {
										String nameAssigner = (altNamesArr[i].indexOf("=") == altNamesArr[i].lastIndexOf("="))? null: altNamesArr[i].substring(altNamesArr[i].indexOf("=") + 1,altNamesArr[i].lastIndexOf("="));
										String partyName = altNamesArr[i].substring(altNamesArr[i].lastIndexOf("=") + 1);
										ASN1EncodableVector vectori = new ASN1EncodableVector();
										if (nameAssigner != null)
											vectori.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
										vectori.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
										DERSequence seq = new DERSequence(vectori);
										names[i] = new GeneralName(GeneralName.ediPartyName, seq);
									} else if (altNamesArr[i].contains("uniformResourceIdentifier="))
										names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, altNamesArr[i].substring(altNamesArr[i].indexOf("uniformResourceIdentifier=") + 26));
									else if (altNamesArr[i].contains("iPAddress"))
										names[i] = new GeneralName(GeneralName.iPAddress,altNamesArr[i].substring(altNamesArr[i].indexOf("iPAddress=") + 10));
									else if (altNamesArr[i].contains("registeredID"))
										names[i] = new GeneralName(GeneralName.registeredID,altNamesArr[i].substring(altNamesArr[i].indexOf("registeredID=") + 13));
									else {
										JOptionPane.showMessageDialog(null, "Invalid SAN type", "Error", JOptionPane.ERROR_MESSAGE);
										return false;
									}
								}
								gen.addExtension(Extension.subjectAlternativeName, access.isCritical(Constants.SAN),new GeneralNames(names));
							} catch (Exception e) {
								e.printStackTrace();
								return false;
							}

			// ---------------------------EXTENSIONS-------------------------

			X509CertificateHolder certHolder = gen.build(signer);

			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
			Certificate[] chain = new Certificate[1];
			chain[0] = cert;

			keystore.setKeyEntry(keypair_name, pr, null, chain);

			fos = new FileOutputStream("keystore.p12");
			keystore.store(fos, "password".toCharArray());

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return true;
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) {
		FileOutputStream fos = null;

		try {
			X509Certificate CAcert = (X509Certificate) keystore.getCertificate(keypair_name);
			X509CertificateHolder CAcertHolder = new JcaX509CertificateHolder(CAcert);

			// -------------------------------------------------------------------------------

			X500Name subject = new X500Name(access.getSubject());
			Date notBefore = access.getNotBefore();
			Date notAfter = access.getNotAfter();
			BigInteger serial = new BigInteger(access.getSerialNumber());

			X509v3CertificateBuilder gen = new JcaX509v3CertificateBuilder(CAcertHolder.getSubject(), serial, notBefore, notAfter,
					subject, CSRPublicKey);
			ContentSigner signer = new JcaContentSignerBuilder(algorithm).setProvider("BC")
					.build((PrivateKey) keystore.getKey(keypair_name, null));

			// ---------------------------EXTENSIONS-------------------------

			// ---------------------------EKU-------------------------

			boolean[] usages = access.getExtendedKeyUsage();
			Vector<KeyPurposeId> vector = new Vector<>();
			for (int i = 0; i < Constants.NUM_OF_EKU; i++) {
				if (usages[i] == true) {
					switch (i) {
					case 0:
						vector.add(KeyPurposeId.anyExtendedKeyUsage);
						break;
					case 1:
						vector.add(KeyPurposeId.id_kp_serverAuth);
						break;
					case 2:
						vector.add(KeyPurposeId.id_kp_clientAuth);
						break;
					case 3:
						vector.add(KeyPurposeId.id_kp_codeSigning);
						break;
					case 4:
						vector.add(KeyPurposeId.id_kp_emailProtection);
						break;
					case 5:
						vector.add(KeyPurposeId.id_kp_timeStamping);
						break;
					case 6:
						vector.add(KeyPurposeId.id_kp_OCSPSigning);
						break;
					}
				}
			}

			if (!vector.isEmpty()) {
				@SuppressWarnings("deprecation")
				ExtendedKeyUsage ext3 = new ExtendedKeyUsage(vector);

				gen.addExtension(Extension.extendedKeyUsage, access.isCritical(Constants.EKU), ext3);
			}

			// SUBJECT ALTERNATIVE NAME

						String[] altNamesArr = access.getAlternativeName(Constants.SAN);
						if (altNamesArr.length > 0)
							try {
								GeneralName[] names = new GeneralName[altNamesArr.length];
								for (int i = 0; i < altNamesArr.length; i++) {
									if(altNamesArr[i].contains("dNSName="))
										names[i]= new GeneralName(GeneralName.dNSName, altNamesArr[i].substring(altNamesArr[i].indexOf("dNSName=")+8));
									else if (altNamesArr[i].contains("rfc822Name="))
										names[i] = new GeneralName(GeneralName.rfc822Name,altNamesArr[i].substring(altNamesArr[i].indexOf("rfc822Name=") + 11));
									else if (altNamesArr[i].contains("x400Address"))
										names[i] = new GeneralName(GeneralName.x400Address, new DERUTF8String(altNamesArr[i].substring(altNamesArr[i].indexOf("x400Address=") + 12)));
									else if (altNamesArr[i].contains("otherName=")) {

										String otherTypeOid = altNamesArr[i].substring(altNamesArr[i].indexOf("=") + 1,altNamesArr[i].lastIndexOf("="));
										ASN1ObjectIdentifier type = new ASN1ObjectIdentifier(otherTypeOid);
										String otherValue = altNamesArr[i].substring(altNamesArr[i].lastIndexOf("=") + 1);
										ASN1EncodableVector vectori = new ASN1EncodableVector();
										vectori.add(type);
										vectori.add(new DERTaggedObject(true, 0, new DERUTF8String(otherValue)));
										DERSequence seq = new DERSequence(vectori);
										names[i] = new GeneralName(GeneralName.otherName, seq);
									} else if (altNamesArr[i].contains("directoryName="))
										names[i] = new GeneralName(GeneralName.directoryName,altNamesArr[i].substring(altNamesArr[i].indexOf("directoryName=") + 14));
									else if (altNamesArr[i].contains("ediPartyName=")) {
										String nameAssigner = (altNamesArr[i].indexOf("=") == altNamesArr[i].lastIndexOf("="))? null: altNamesArr[i].substring(altNamesArr[i].indexOf("=") + 1,altNamesArr[i].lastIndexOf("="));
										String partyName = altNamesArr[i].substring(altNamesArr[i].lastIndexOf("=") + 1);
										ASN1EncodableVector vectori = new ASN1EncodableVector();
										if (nameAssigner != null)
											vectori.add(new DERTaggedObject(false, 0, new DirectoryString(nameAssigner)));
										vectori.add(new DERTaggedObject(false, 1, new DirectoryString(partyName)));
										DERSequence seq = new DERSequence(vectori);
										names[i] = new GeneralName(GeneralName.ediPartyName, seq);
									} else if (altNamesArr[i].contains("uniformResourceIdentifier="))
										names[i] = new GeneralName(GeneralName.uniformResourceIdentifier, altNamesArr[i].substring(altNamesArr[i].indexOf("uniformResourceIdentifier=") + 26));
									else if (altNamesArr[i].contains("iPAddress"))
										names[i] = new GeneralName(GeneralName.iPAddress,altNamesArr[i].substring(altNamesArr[i].indexOf("iPAddress=") + 10));
									else if (altNamesArr[i].contains("registeredID"))
										names[i] = new GeneralName(GeneralName.registeredID,altNamesArr[i].substring(altNamesArr[i].indexOf("registeredID=") + 13));
									else {
										JOptionPane.showMessageDialog(null, "Invalid SAN type", "Error", JOptionPane.ERROR_MESSAGE);
										return false;
									}
								}
								gen.addExtension(Extension.subjectAlternativeName, access.isCritical(Constants.SAN),new GeneralNames(names));
							} catch (Exception e) {
								e.printStackTrace();
								return false;
							}
			
			// ---------------------------EXTENSIONS-------------------------

			X509CertificateHolder newCertHolder = gen.build(signer);

			// -------------------------------------------------------------------------------

			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(signer,
							(X509Certificate) CAcert));
			
			ArrayList<X509CertificateHolder> holderList = new ArrayList<>();
			holderList.add(newCertHolder);
			holderList.add(CAcertHolder);
			CollectionStore<X509CertificateHolder> store = new CollectionStore<>(holderList);
			generator.addCertificates(store);

			CMSTypedData CMSData = new CMSProcessableByteArray(new X500Name(access.getSubject()).getEncoded());
			CMSSignedData signedData = generator.generate(CMSData, true);

			fos = new FileOutputStream(file);
			fos.write(signedData.getEncoded());

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		} finally {
			try {
				CSRPublicKey = null;
				if (fos != null)
					fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}

