﻿using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Xml.Linq;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Extension methods for Saml2Assertion
    /// </summary>
    public static class Saml2AssertionExtensions
    {
        /// <summary>
        /// Writes out the assertion as an XElement.
        /// </summary>
        /// <param name="assertion">The assertion to create xml for.</param>
        /// <returns>XElement</returns>
        public static XElement ToXElement(this Saml2Assertion assertion)
        {
            if(assertion == null)
            {
                throw new ArgumentNullException("assertion");
            }

            var xml = new XElement(Saml2Namespaces.Saml2 + "Assertion",
                new XAttribute(XNamespace.Xmlns + "saml2", Saml2Namespaces.Saml2Name),
                new XAttribute("Version", assertion.Version),
                new XAttribute("ID", assertion.Id.Value),
                new XAttribute("IssueInstant", 
                    assertion.IssueInstant.ToString("s", CultureInfo.InvariantCulture) + "Z"),
                new XElement(Saml2Namespaces.Saml2 + "Issuer", assertion.Issuer.Value));

            if (assertion.Subject != null)
            {
                xml.Add(new XElement(Saml2Namespaces.Saml2 + "Subject",
                    new XElement(Saml2Namespaces.Saml2 + "NameID",
                    assertion.Subject.NameId.Value),
                    new XElement(Saml2Namespaces.Saml2 + "SubjectConfirmation",
                        new XAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer"))
                    ));
            }

            if(assertion.Conditions != null && assertion.Conditions.NotOnOrAfter != null)
            {
                xml.Add(new XElement(Saml2Namespaces.Saml2 + "Conditions",
                    new XAttribute("NotOnOrAfter", 
                        assertion.Conditions.NotOnOrAfter.Value.ToString("s", 
                        CultureInfo.InvariantCulture) + "Z")));
            }

            return xml;
        }
    }
}
