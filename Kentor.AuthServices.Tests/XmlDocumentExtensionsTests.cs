﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using FluentAssertions;

namespace Kentor.AuthServices.Tests
{
    [TestClass]
    public class XmlDocumentExtensionsTests
    {
        public static readonly X509Certificate2 TestCert = new X509Certificate2("Kentor.AuthServices.Tests.pfx");

        [TestMethod]
        public void XmlDocumentExtensions_Sign_Nullcheck_xmlDocument()
        {
            XmlDocument xd = null;
            Action a = () => xd.Sign(TestCert);

            a.ShouldThrow<ArgumentNullException>().And.Message.Contains("xmlDocument");
        }

        [TestMethod]
        public void XmlDocumentExtensions_Sign_Nullcheck_Cert()
        {
            XmlDocument xd = new XmlDocument();
            Action a = () => xd.Sign(null);

            a.ShouldThrow<ArgumentNullException>().And.Message.Contains("cert");
        }

        [TestMethod]
        public void XmlDocumentExtensions_Sign()
        {
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml("<root ID=\"roolElementId\"><content>Some Content</content></root>");

            xmlDoc.Sign(TestCert);

            var signature = xmlDoc.DocumentElement["Signature", SignedXml.XmlDsigNamespaceUrl];

            var signedXml = new SignedXml(xmlDoc);

            signedXml.LoadXml(signature);

            signedXml.CheckSignature(TestCert, true).Should().BeTrue();
        }
    }
}
