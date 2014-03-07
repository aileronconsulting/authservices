using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Web;
using System.Xml;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Represents a SAML2 response according to 3.3.3. The class is immutable (to an
    /// external observer. Internal state is lazy initiated).
    /// </summary>
    public class Saml2Response : ISaml2Message
    {
        /// <summary>Holds all assertion element nodes</summary>
        private XmlElement[] _allAssertionElementNodes;

        /// <summary>
        /// 
        /// </summary>
        public bool HasEncryptedAssertions { get; set; }

        /// <summary>
        /// Read the supplied Xml and parse it into a response.
        /// </summary>
        /// <param name="xml">xml data.</param>
        /// <returns>Saml2Response</returns>
        /// <exception cref="XmlException">On xml errors or unexpected xml structure.</exception>
        public static Saml2Response Read(string xml)
        {
            var x = new XmlDocument { PreserveWhitespace = true };
            x.LoadXml(xml);
            var encryptedAssertions = x.GetElementsByTagName("EncryptedAssertion", Saml2Namespaces.Saml2Name);
            var isEncrypted = encryptedAssertions.Count > 0;
            if (isEncrypted)
            {
                var certificateFile = ConfigurationManager.AppSettings["certificateLocation"];
                var certificateFilePwd = ConfigurationManager.AppSettings["certificatePassword"];
                certificateFile = HttpContext.Current.Server.MapPath(certificateFile);
                var store = new X509Store(StoreLocation.CurrentUser);
                var cert = new X509Certificate2(certificateFile, certificateFilePwd);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                store.Close();
                var exml = new EncryptedXml(x);
                exml.DecryptDocument();
            }

            if (x.DocumentElement != null && (x.DocumentElement.LocalName != "Response"
                                              || x.DocumentElement.NamespaceURI != Saml2Namespaces.Saml2P))
            {
                throw new XmlException("Expected a SAML2 assertion document");
            }

            if (x.DocumentElement != null && x.DocumentElement.Attributes["Version"].Value != "2.0")
            {
                throw new XmlException("Wrong or unsupported SAML2 version");
            }

            return new Saml2Response(x, isEncrypted);
        }

        private Saml2Response(XmlDocument xml, bool isEncrypted)
        {
            _xmlDocument = xml;
            HasEncryptedAssertions = isEncrypted;
            string statusString = string.Empty;
            if (xml.DocumentElement != null)
            {
                id = new Saml2Id(xml.DocumentElement.Attributes["ID"].Value);

                issueInstant = DateTime.Parse(xml.DocumentElement.Attributes["IssueInstant"].Value,
                                              CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);

                var xmlElement = xml.DocumentElement["Status", Saml2Namespaces.Saml2PName];
                if (xmlElement != null)
                {
                    var element = xmlElement["StatusCode", Saml2Namespaces.Saml2PName];
                    if (element != null)
                    {
                        statusString = element.Attributes["Value"].Value;
                    }
                }
            }

            status = StatusCodeHelper.FromString(statusString);

            if (_xmlDocument.DocumentElement != null)
            {
                issuer = _xmlDocument.DocumentElement["Issuer", Saml2Namespaces.Saml2Name].GetTrimmedTextIfNotNull();

                var destinationUriString = _xmlDocument.DocumentElement.Attributes["Destination"].GetValueIfNotNull();
                if (destinationUriString != null)
                {
                    destinationUri = new Uri(destinationUriString);
                }
            }

        }

        /// <summary>
        /// Create a response with the supplied data.
        /// </summary>
        /// <param name="issuer">Issuer of the response.</param>
        /// <param name="issuerCertificate">The certificate to use when signing
        /// this response in XML form.</param>
        /// <param name="destinationUri">The destination Uri for the message</param>
        /// <param name="claimsIdentities">Claims identities to be included in the 
        /// response. Each identity is translated into a separate assertion.</param>
        public Saml2Response(string issuer, X509Certificate2 issuerCertificate,
            Uri destinationUri, params ClaimsIdentity[] claimsIdentities)
        {
            this.issuer = issuer;
            this.claimsIdentities = claimsIdentities;
            this._issuerCertificate = issuerCertificate;
            this.destinationUri = destinationUri;
            id = new Saml2Id("id" + Guid.NewGuid().ToString("N"));
            status = Saml2StatusCode.Success;
        }

        private readonly X509Certificate2 _issuerCertificate;

        private XmlDocument _xmlDocument;

        /// <summary>
        /// The response as an xml docuemnt. Either the original xml, or xml that is
        /// generated from supplied data.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1059:MembersShouldNotExposeCertainConcreteTypes", MessageId = "System.Xml.XmlNode")]
        public XmlDocument XmlDocument
        {
            get
            {
                if (_xmlDocument == null)
                {
                    CreateXmlDocument();
                }

                return _xmlDocument;
            }
        }

        /// <summary>
        /// SAML Message name for responses, hard coded to SAMLResponse.
        /// </summary>
        public string MessageName
        {
            get
            {
                return "SAMLResponse";
            }
        }

        /// <summary>
        /// string representation of the Saml2Response serialized to xml.
        /// </summary>
        /// <returns>string containing xml.</returns>
        public string ToXml()
        {
            return XmlDocument.OuterXml;
        }

        private void CreateXmlDocument()
        {
            var xml = new XmlDocument();
            xml.AppendChild(xml.CreateXmlDeclaration("1.0", null, null));

            var responseElement = xml.CreateElement("saml2p", "Response", Saml2Namespaces.Saml2PName);

            if (DestinationUri != null)
            {
                responseElement.SetAttributeNode("Destination", "").Value = DestinationUri.ToString();
            }

            responseElement.SetAttributeNode("ID", "").Value = id.Value;
            responseElement.SetAttributeNode("Version", "").Value = "2.0";
            responseElement.SetAttributeNode("IssueInstant", "").Value =
                DateTime.UtcNow.ToString("s", CultureInfo.InvariantCulture) + "Z";
            xml.AppendChild(responseElement);

            var issuerElement = xml.CreateElement("saml2", "Issuer", Saml2Namespaces.Saml2Name);
            issuerElement.InnerText = issuer;
            responseElement.AppendChild(issuerElement);

            var statusElement = xml.CreateElement("saml2p", "Status", Saml2Namespaces.Saml2PName);
            var statusCodeElement = xml.CreateElement("saml2p", "StatusCode", Saml2Namespaces.Saml2PName);
            statusCodeElement.SetAttributeNode("Value", "").Value = StatusCodeHelper.FromCode(Status);
            statusElement.AppendChild(statusCodeElement);
            responseElement.AppendChild(statusElement);

            foreach (var ci in claimsIdentities)
            {
                responseElement.AppendChild(xml.ReadNode(
                    ci.ToSaml2Assertion(issuer).ToXElement().CreateReader()));
            }

            _xmlDocument = xml;

            xml.Sign(_issuerCertificate);
        }

        readonly Saml2Id id;

        /// <summary>
        /// Id of the response message.
        /// </summary>
        public Saml2Id Id { get { return id; } }

        readonly DateTime issueInstant;

        /// <summary>
        /// Issue instant of the response message.
        /// </summary>
        public DateTime IssueInstant { get { return issueInstant; } }

        readonly Saml2StatusCode status;

        /// <summary>
        /// Status code of the message according to the SAML2 spec section 3.2.2.2
        /// </summary>
        public Saml2StatusCode Status { get { return status; } }

        readonly string issuer;

        /// <summary>
        /// Issuer (= sender) of the response.
        /// </summary>
        public string Issuer
        {
            get
            {
                return issuer;
            }
        }

        readonly Uri destinationUri;

        /// <summary>
        /// The destination of the response message.
        /// </summary>
        public Uri DestinationUri
        {
            get
            {
                return destinationUri;
            }
        }

        bool _valid, _validated;

        /// <summary>Gets all assertion element nodes from this response message.</summary>
        /// <value>All assertion element nodes.</value>
        protected IEnumerable<XmlElement> AllAssertionElementNodes
        {
            get
            {
                if (_allAssertionElementNodes == null)
                {
                    // check for encryption
                    var documentElement = XmlDocument.DocumentElement;
                    if (documentElement != null)
                        _allAssertionElementNodes =
                            documentElement.ChildNodes.Cast<XmlNode>().Where(node => node.NodeType == XmlNodeType.Element).Cast<XmlElement>()
                                .Where(xe => (xe.LocalName == "Assertion" || xe.LocalName == "EncryptedAssertion") && xe.NamespaceURI == Saml2Namespaces.Saml2Name)
                                .ToArray();
                }

                return _allAssertionElementNodes;
            }
        }

        /// <summary>
        /// Validates the response.
        /// </summary>
        /// <param name="idpCertificate">Idp certificate that should have signed the reponse</param>
        /// <returns>Is the response signed by the Idp and fulfills other formal requirements?</returns>
        public bool Validate(X509Certificate2 idpCertificate)
        {
            if (_validated)
            {
                return _valid;
            }

            // If the response message is signed, we check just this signature because the whole content has to be correct then
            var signedRootElement = XmlDocument.DocumentElement;
            if (signedRootElement != null)
            {
                var responseSignature = signedRootElement["Signature", SignedXml.XmlDsigNamespaceUrl];
                if (responseSignature != null)
                {
                    _valid = CheckSignature(signedRootElement, idpCertificate);
                }
                else
                {
                    // If the response message is not signed, all assersions have to be signed correctly
                    foreach (var assertionNode in AllAssertionElementNodes)
                    {
                        _valid = CheckSignature(assertionNode, idpCertificate);
                        if (!_valid)
                        {
                            break;
                        }
                    }
                }
            }

            _validated = true;

            return _valid;
        }

        /// <summary>Checks the signature.</summary>
        /// <param name="signedXml">The signed XML.</param>
        /// <param name="signedRootElement">The signed root element.</param>
        /// <param name="idpCertificate">The idp certificate.</param>
        /// <returns><c>true</c> if the whole signature was successful; otherwise <c>false</c></returns>
        private static bool CheckSignature(XmlElement signedRootElement, X509Certificate2 idpCertificate)
        {
            var xmlDocument = new XmlDocument { PreserveWhitespace = true };
            xmlDocument.LoadXml(signedRootElement.OuterXml);
            var isEncryptedAssertion = xmlDocument.DocumentElement != null && xmlDocument.DocumentElement.Name == "EncryptedAssertion";
            if (isEncryptedAssertion)
            {
                var signature = (XmlElement)xmlDocument.GetElementsByTagName("Signature")[0];
                if (signature == null)
                {
                    return false;
                }
                CryptoConfig.AddAlgorithm(typeof(Rpkcs1Sha256SignatureDescription),
                                          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                var signedXml = new SignedXml(xmlDocument);
                signedXml.LoadXml(signature);

                var signedRootElementId = "#" + ((XmlElement)signedRootElement.ChildNodes[0]).GetAttribute("ID");
                if (
                    signedXml.SignedInfo.References.Cast<Reference>().All(
                        reference => reference.Uri != signedRootElementId))
                {
                    return false;
                }

                return signedXml.CheckSignature(idpCertificate, true);
            }
            else
            {
                var signature = xmlDocument.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];
                if (signature == null)
                {
                    return false;
                }
                CryptoConfig.AddAlgorithm(typeof(Rpkcs1Sha256SignatureDescription),
                                          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                var signedXml = new SignedXml(xmlDocument);
                signedXml.LoadXml(signature);

                var signedRootElementId = "#" + signedRootElement.GetAttribute("ID");
                if (
                    signedXml.SignedInfo.References.Cast<Reference>().All(
                        reference => reference.Uri != signedRootElementId))
                {
                    return false;
                }

                return signedXml.CheckSignature(idpCertificate, true);
            }
        }

        private void ThrowOnNotValid()
        {
            if (!_validated)
            {
                throw new InvalidOperationException("The Saml2Response must be validated first.");
            }
            if (!_valid)
            {
                throw new InvalidOperationException("The Saml2Response didn't pass validation");
            }
        }

        private IEnumerable<ClaimsIdentity> claimsIdentities;
        private Exception createClaimsException;

        /// <summary>
        /// Extract claims from the assertions contained in the response.
        /// </summary>
        /// <returns>ClaimsIdentities</returns>
        // Method might throw expections so make it a method and not a property.
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
        public IEnumerable<ClaimsIdentity> GetClaims()
        {
            if (createClaimsException != null)
            {
                throw createClaimsException;
            }

            if (claimsIdentities == null)
            {
                try
                {
                    claimsIdentities = CreateClaims().ToList();
                }
                catch (Exception ex)
                {
                    createClaimsException = ex;
                    throw;
                }
            }

            return claimsIdentities;
        }

        private IEnumerable<ClaimsIdentity> CreateClaims()
        {
            ThrowOnNotValid();

            foreach (var assertionNode in AllAssertionElementNodes)
            {
                XmlNode node = assertionNode;
                if (HasEncryptedAssertions)
                {
                    node = assertionNode.FirstChild;
                }
                using (var reader = new XmlNodeReader(node))
                {
                    var handler = MorePublicSaml2SecurityTokenHandler.DefaultInstance;

                    var token = (Saml2SecurityToken)MorePublicSaml2SecurityTokenHandler.DefaultInstance.ReadToken(reader);
                    handler.DetectReplayedToken(token);

                    var validateAudience = token.Assertion.Conditions.AudienceRestrictions.Count > 0;

                    handler.ValidateConditions(token.Assertion.Conditions, validateAudience);

                    yield return handler.CreateClaims(token);
                }
            }
        }
    }

    /// <summary>
    /// 
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Rpkcs"), System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704:IdentifiersShouldBeSpelledCorrectly", MessageId = "Sha")]
    public class Rpkcs1Sha256SignatureDescription : SignatureDescription
    {
        /// <summary>
        /// 
        /// </summary>
        public Rpkcs1Sha256SignatureDescription()
        {
            base.KeyAlgorithm = "System.Security.Cryptography.RSACryptoServiceProvider";
            base.DigestAlgorithm = "System.Security.Cryptography.SHA256Managed";
            base.FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
            base.DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            var asymmetricSignatureDeformatter = (AsymmetricSignatureDeformatter)
                CryptoConfig.CreateFromName(base.DeformatterAlgorithm);
            asymmetricSignatureDeformatter.SetKey(key);
            asymmetricSignatureDeformatter.SetHashAlgorithm("SHA256");
            return asymmetricSignatureDeformatter;
        }
    }
}
