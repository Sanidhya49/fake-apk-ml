import React, { useState } from "react";
import {
  HiChevronDown,
  HiChevronUp,
  HiQuestionMarkCircle,
} from "react-icons/hi";
import { scrollToSection } from "../../utils/scrollUtils";

const FAQSection = () => {
  const [openItems, setOpenItems] = useState(new Set([0])); // First item open by default

  const faqData = [
    {
      question: "How does the APK security analysis work?",
      answer:
        "Our advanced AI system performs multiple security checks including code integrity analysis, digital signature verification, permission analysis, malware signature detection, and behavioral pattern analysis. The process uses machine learning models trained on millions of applications to identify potential threats.",
    },
    {
      question: "Is my APK file stored on your servers?",
      answer:
        "No, absolutely not. We prioritize your privacy and security. All analysis is performed in real-time and no file data is stored on our servers. Your APK files are processed temporarily and immediately discarded after analysis completion.",
    },
    {
      question: "How accurate is the threat detection?",
      answer:
        "Our system maintains a 99.7% accuracy rate based on extensive testing with known malicious and legitimate banking applications. However, no system is 100% perfect, so we recommend always downloading apps from official sources like Google Play Store or Apple App Store.",
    },
    {
      question: "What types of threats can be detected?",
      answer:
        "We detect various threats including malware signatures, trojans, suspicious permission requests, code obfuscation, unauthorized network connections, data harvesting attempts, and behavioral anomalies commonly found in fake banking applications.",
    },
    {
      question: "How long does the analysis take?",
      answer:
        "Most analyses complete within 15-30 seconds, depending on the APK file size and complexity. Our real-time processing ensures you get immediate results without long waiting periods.",
    },
    {
      question: "Can I use this for non-banking applications?",
      answer:
        "While our system is specifically optimized for banking and financial applications, it can provide valuable security insights for other types of APK files as well. However, the accuracy and recommendations are tailored for financial apps.",
    },
    {
      question: "What should I do if an app is marked as suspicious?",
      answer:
        "If an application is marked as suspicious or dangerous, we strongly recommend not installing it. Instead, download the official banking app directly from your bank's website or verified app stores. Contact your bank if you're unsure about an application's legitimacy.",
    },
    {
      question: "Is there a file size limit?",
      answer:
        "Yes, we currently support APK files up to 100MB in size. This covers the vast majority of banking applications. Larger files may require special handling or extended processing time.",
    },
  ];

  const toggleItem = (index) => {
    const newOpenItems = new Set(openItems);
    if (newOpenItems.has(index)) {
      newOpenItems.delete(index);
    } else {
      newOpenItems.add(index);
    }
    setOpenItems(newOpenItems);
  };

  return (
    <section
      id="faq"
      className="py-16 md:py-24 bg-white dark:bg-gray-900 relative overflow-hidden"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-2">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      <div className="relative z-10 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16 animate-fade-up">
          <div className="inline-flex items-center px-6 py-3 rounded-full bg-primary-50 dark:bg-primary-900/20 border border-primary-200/50 dark:border-primary-700/50 mb-6">
            <HiQuestionMarkCircle className="w-5 h-5 text-primary-400 mr-2" />
            <span className="text-primary-700 dark:text-primary-300 font-medium">
              Frequently Asked Questions
            </span>
          </div>

          <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-white mb-4">
            Everything You Need
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-400 to-teal-400">
              to Know
            </span>
          </h2>
          <p className="text-xl text-gray-300">
            Get answers to common questions about APK security analysis
          </p>
        </div>

        {/* FAQ Items */}
        <div
          className="space-y-4 animate-fade-up"
          style={{ animationDelay: "200ms" }}
        >
          {faqData.map((item, index) => (
            <div
              key={index}
              className="bg-gray-50 dark:bg-gray-800/50 rounded-2xl border border-gray-700/50 overflow-hidden shadow-sm hover:shadow-md transition-all duration-300"
            >
              <button
                onClick={() => toggleItem(index)}
                className="w-full px-6 md:px-8 py-6 text-left flex items-center justify-between hover:bg-gray-100 dark:hover:bg-gray-800 transition-all duration-200"
              >
                <h3 className="text-lg md:text-xl font-semibold text-gray-900 dark:text-white pr-4">
                  {item.question}
                </h3>
                <div className="flex-shrink-0">
                  {openItems.has(index) ? (
                    <HiChevronUp className="w-6 h-6 text-primary-400" />
                  ) : (
                    <HiChevronDown className="w-6 h-6 text-gray-400 dark:text-gray-500" />
                  )}
                </div>
              </button>

              {openItems.has(index) && (
                <div className="px-6 md:px-8 pb-6 animate-fade-in">
                  <div className="border-t border-gray-700/50 pt-6">
                    <p className="text-gray-300 leading-relaxed">
                      {item.answer}
                    </p>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Additional Help */}
        <div
          className="mt-16 text-center animate-fade-up"
          style={{ animationDelay: "400ms" }}
        >
          <div className="p-8 rounded-2xl bg-gradient-to-r from-primary-50 to-teal-50 dark:from-primary-900/20 dark:to-teal-900/20 border border-primary-200/50 dark:border-primary-700/50">
            <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
              Still have questions?
            </h3>
            <p className="text-gray-300 mb-6">
              Our security experts are here to help you understand APK threats
              and protection
            </p>
            <button
              onClick={() => scrollToSection("about")}
              className="inline-flex items-center px-8 py-3 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transform hover:-translate-y-1 transition-all duration-300"
            >
              <HiQuestionMarkCircle className="w-5 h-5 mr-2" />
              Contact Support
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default FAQSection;

