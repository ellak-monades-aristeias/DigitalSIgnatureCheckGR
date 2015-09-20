using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using iTextSharp.text.pdf.security;
using iTextSharp.text.pdf;
using iTextSharp.text;

using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using System.IO;
using System.Web;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;


namespace Utils
{

    #region "Help Classes"
    

    public class MessageReport
    {
        public struct Results
        {
            public string resultText { get; set; }
            public bool result { get; set; }
        }

       
        public struct Signature
        {
            public bool visible { get; set; }
            public string digestAlgorithm { get; set; }
            public string encryptionAlgorithm { get; set; }
            public string signerName { get; set; }
            public string signerAlternativeName { get; set; }
            public string signDate { get; set; }
            public string signLocation { get; set; }
            public string signReason { get; set; }
            public string signatureType { get; set; }
            public bool isTimestampped { get; set; }
            public string timestampDate { get; set; }
            public string timestampName { get; set; }
            public bool isRevocationValid { get; set; }
            public bool isCoveringWholeDocument { get; set; }
            public bool isIntegral { get; set; }
            public bool isValidDateSigning { get; set; }
            public bool isValidToday { get; set; }

            public Cert Certificate { get; set; }
            public Results Results { get; set; }

        }

        public bool checkCompleted { get; set; }
        public string StatusText { get; set; }
        public int signaturesCount { get; set; }
        public List<Signature> Signatures { get; set; }

        public MessageReport() //constructor
        {
            this.signaturesCount = 0;
            this.Signatures = new List<Signature>();
            this.checkCompleted = false; // initialize completed status 
        }

    }

    #endregion

    /// <summary>
    /// Signature Validator Class
    /// </summary>
    public static class SignatureValidator
    {

        readonly private static List<X509Certificate> certificates = new List<X509Certificate>();
        public static String ROOT1 = System.Web.HttpRuntime.BinDirectory + "//resources//ROOT1.cer";
        public static String ROOT2 = System.Web.HttpRuntime.BinDirectory + "//resources//ROOT2.cer";
        public static String ROOT3 = System.Web.HttpRuntime.BinDirectory + "//resources//ROOT3.cer";

        public static String OCSP1 = System.Web.HttpRuntime.BinDirectory + "//resources//OCSP1.cer";
        public static String OCSP2 = System.Web.HttpRuntime.BinDirectory + "//resources//OCSP2.cer";
        public static String OCSP3 = System.Web.HttpRuntime.BinDirectory + "//resources//OCSP3.cer";

       
        public static String HARD_CERTIFICATE_POLICY_ID = "1.2.300.0.110001.1.7.1.1.1";

        #region "Private Methods"

        private static bool CheckRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, DateTime date)
        {
            List<BasicOcspResp> ocsps = new List<BasicOcspResp>();
            if (pkcs7.Ocsp != null)
                ocsps.Add(pkcs7.Ocsp);
            OcspVerifier ocspVerifier = new OcspVerifier(null, ocsps);
            List<VerificationOK> verification =
                ocspVerifier.Verify(signCert, issuerCert, date);
            if (verification.Count == 0)
            {
                List<X509Crl> crls = new List<X509Crl>();
                if (pkcs7.CRLs != null)
                    foreach (X509Crl crl in pkcs7.CRLs)
                        crls.Add(crl);

                if (crls.Count > 0)
                {
                    CrlVerifier crlVerifier = new CrlVerifier(null, crls);
                    verification.AddRange(crlVerifier.Verify(signCert, issuerCert, date));
                }

            }
            if (verification.Count == 0)
                return false;
            else
                foreach (VerificationOK v in verification)
                    Console.WriteLine(v);

            return (verification.Count > 0);
        }
        /// <summary>
        /// Checks Certificate Policies for policy : "1.2.300.0.110001.1.7.1.1.1" which indicate a hard certificate
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns>true/false</returns>
        private static bool isHardCertificatePolicyOidt(X509Certificate certificate)
        {

            X509Extension certPolicies =
                certificate.CertificateStructure.TbsCertificate.Extensions.GetExtension(X509Extensions.CertificatePolicies);

            DerSequence seq = certPolicies.GetParsedValue() as DerSequence;

            foreach (Asn1Encodable seqItem in seq)
            {
                DerSequence subSeq = seqItem as DerSequence;
                if (subSeq == null)
                    continue;

                foreach (Asn1Encodable subSeqItem in subSeq)
                {
                    DerObjectIdentifier oid = subSeqItem as DerObjectIdentifier;
                    if (oid == null)
                        continue;

                    if (oid.Id == HARD_CERTIFICATE_POLICY_ID) return true;
                }
                return false;

            }
            return false;
        }


        private static MessageReport.Cert GetCertificateInfo(X509Certificate cert, DateTime signDate)
        {

            MessageReport.Cert c = new MessageReport.Cert();

            c.isHardCertificate = isHardCertificatePolicyOidt(cert);

            c.issuer = cert.IssuerDN.ToString();
            c.subject = cert.SubjectDN.ToString();
            c.validFrom = cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss.ff");
            c.validTo = cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss.ff");


            try
            {
                cert.CheckValidity(signDate);
                c.statusDaySigning = "Έγκυρο κατά το χρόνο υπογραφής";

            }
            catch (CertificateExpiredException e)
            {
                c.statusDaySigning = "Έίχε λήξει κατά το χρόνο υπογραφής.";
            }
            catch (CertificateNotYetValidException e)
            {
                c.statusDaySigning = "Δεν ήταν έγκυρο κατά το χρόνο υπογραφής";
            }

            try
            {
                cert.CheckValidity();
                c.statusToday = "Έγκυρο";
            }
            catch (CertificateExpiredException e)
            {
                c.statusToday = "Έχει λήξει";
            }
            catch (CertificateNotYetValidException e)
            {
                c.statusToday = "Μη έγκυρο";
            }

            return c;
        }


        private static PdfPKCS7 VerifySignature(AcroFields fields, String name, ref MessageReport.Signature sigInfo)
        {

            sigInfo.isCoveringWholeDocument = fields.SignatureCoversWholeDocument(name);

            PdfPKCS7 pkcs7 = fields.VerifySignature(name);

            sigInfo.isIntegral = pkcs7.Verify();

            X509Certificate[] certs = pkcs7.SignCertificateChain;
            DateTime cal = pkcs7.SignDate;

            IList<VerificationException> errors = CertificateVerification.VerifyCertificates(certs, certificates, null, cal);
            if (errors == null)
                Console.WriteLine("Certificates verified against the KeyStore");
            else
                foreach (object error in errors)
                    Console.WriteLine(error);
            for (int i = 0; i < certs.Length; ++i)
            {
                X509Certificate cert = certs[i];

            }
            X509Certificate signCert = certs[0];
            X509Certificate issuerCert = (certs.Length > 1 ? certs[1] : null);

            sigInfo.Certificate = GetCertificateInfo(signCert, cal.ToLocalTime());

            sigInfo.isValidDateSigning = CheckRevocation(pkcs7, signCert, issuerCert, cal);

            sigInfo.isValidToday = CheckRevocation(pkcs7, signCert, issuerCert, DateTime.Now.AddDays(-1));



            return pkcs7;

        }


        private static MessageReport.Signature InspectSignature(AcroFields fields, String name, SignaturePermissions perms)
        {
            MessageReport.Signature sigInfo = new MessageReport.Signature();

            IList<AcroFields.FieldPosition> fps = fields.GetFieldPositions(name);
            if (fps != null && fps.Count > 0)
            {
                AcroFields.FieldPosition fp = fps[0];
                Rectangle pos = fp.position;
                if (pos.Width == 0 || pos.Height == 0)
                {
                    sigInfo.visible = false;
                }
                else
                {
                    sigInfo.visible = true;
                   
                }
            }

            PdfPKCS7 pkcs7 = VerifySignature(fields, name, ref sigInfo);
            sigInfo.digestAlgorithm = pkcs7.GetHashAlgorithm();
            sigInfo.encryptionAlgorithm = pkcs7.GetEncryptionAlgorithm();
            sigInfo.isRevocationValid = pkcs7.IsRevocationValid();

            
            X509Certificate cert = pkcs7.SigningCertificate;
            sigInfo.signerName = CertificateInfo.GetSubjectFields(cert).GetField("CN");

            if (pkcs7.SignName != null)
                sigInfo.signerName = pkcs7.SignName;

            sigInfo.signDate = pkcs7.SignDate.ToString("yyyy-MM-dd HH:mm:ss.ff");

            if (!pkcs7.TimeStampDate.Equals(DateTime.MaxValue))
            {
                sigInfo.isTimestampped = true;
                sigInfo.timestampDate = pkcs7.TimeStampDate.ToString("yyyy-MM-dd HH:mm:ss.ff");

                TimeStampToken ts = pkcs7.TimeStampToken;
                sigInfo.timestampName = ts.TimeStampInfo.Tsa.ToString();
                
            }
            
            sigInfo.signLocation = pkcs7.Location;
            sigInfo.signReason = pkcs7.Reason;

            PdfDictionary sigDict = fields.GetSignatureDictionary(name);
            PdfString contact = sigDict.GetAsString(PdfName.CONTACTINFO);
            if (contact != null)
                Console.WriteLine("Contact info: " + contact);
            perms = new SignaturePermissions(sigDict, perms);

            sigInfo.signatureType = (perms.Certification ? "certification" : "approval");

           
            return sigInfo;
        }

        private static void UpdateSignatureResults(ref MessageReport.Signature s)
        {
            MessageReport.Results r = new MessageReport.Results();
            string hm = string.Empty;

            r.result = false;

            hm = "Το αρχείο ";

            if (s.Certificate.isHardCertificate == false) hm += "δεν ";
            hm += "έχει υπογραφεί με χρήση πιστοποιητικού σκληρής αποθήκευσης της ΑΠΕΔ,  ";

            hm += "το οποίο ";
            if (s.isValidDateSigning == false) hm += "δεν ";
            hm += " ήταν έγκυρο κατά την ημερομηνία υπογραφής. ";

            hm += "Το αρχείο  ";
            if (s.isIntegral) hm += "δεν ";
            hm += " έχει τροποποιηθεί μετά την υπογραφή του και  ";

            if (s.isTimestampped == false) hm += "δεν ";
            hm += " φέρει ενσωματωμένη χρονοσφραγίδα. ";

            if (s.isValidDateSigning && s.isIntegral && s.isTimestampped && s.Certificate.isHardCertificate)
            {
                r.result = true;
            }

            r.resultText = hm;

            s.Results = r;

        }


        #endregion

         #region "Public Methods"

                public static bool validatePDF(string filename, ref  MessageReport msg)
                {
                    try
                    {


                        X509CertificateParser parser = new X509CertificateParser();

                        if (certificates.Count() == 0)
                        {
                            certificates.Add(parser.ReadCertificate(new FileStream(ROOT1, FileMode.Open)));
                            certificates.Add(parser.ReadCertificate(new FileStream(ROOT2, FileMode.Open)));
                            certificates.Add(parser.ReadCertificate(new FileStream(ROOT3, FileMode.Open)));

                        }


                        PdfReader pdfReader = new PdfReader(filename);

                        AcroFields acroFields = pdfReader.AcroFields;
                        List<String> signatureNames = acroFields.GetSignatureNames();

                        msg.signaturesCount = signatureNames.Count();

                        if (signatureNames.Count == 0)
                        {
                            msg.StatusText = "Δεν βρέθηκαν ψηφιακές υπογραφές στο έγγραφο!";
                            return false;
                        }

                        SignaturePermissions perms = null;
                        MessageReport.Signature sigInfo = new MessageReport.Signature();


                        foreach (String name in signatureNames)
                        {
                          
                            sigInfo = InspectSignature(acroFields, name, perms);
                            UpdateSignatureResults(ref sigInfo); //produce human friendly result text

                            msg.Signatures.Add(sigInfo);

                        }
                        msg.StatusText = String.Format("Ο έλεγχος ολοκληρώθηκε επιτυχώς. Βρέθηκαν {0} ψηφιακές υπογραφές στο έγγραφο!", msg.signaturesCount);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }

                } //end validatePDF
        #endregion


       

    } //end class
} //end namespace
