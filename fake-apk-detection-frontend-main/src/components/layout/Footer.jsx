import React from "react";
import { HiShieldCheck, HiMail, HiGlobeAlt } from "react-icons/hi";
import { BsGithub, BsTwitter, BsLinkedin } from "react-icons/bs";

const Footer = () => {
  return (
    <footer className="bg-gray-900 text-white relative overflow-hidden">
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-5">
        <div className="absolute inset-0 bg-grid-pattern"></div>
      </div>

      <div className="relative z-10">
        {/* Main Footer Content */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-4 py-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {/* Brand Section */}
            <div className="lg:col-span-2">
              <div className="flex items-center space-x-3 mb-6">
                <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-teal-500 shadow-lg">
                  <HiShieldCheck className="w-6 h-6 text-white" />
                </div>
                <div className="flex flex-col">
                  <h1 className="text-2xl font-bold">
                    SecureAPK
                    <span className="text-primary-400 ml-1">Detector</span>
                  </h1>
                  <p className="text-sm text-gray-400">Digital Rakshak</p>
                </div>
              </div>
              <p className="text-gray-300 mb-2 mt-8 leading-relaxed max-w-md">
                An AI-powered tool that scans banking APKs in real time to
                detect malicious code, suspicious permissions, embedded
                trackers, and phishing risks — delivering rapid threat triage
                for security
              </p>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-gray-800">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            <div className="flex flex-col md:flex-row items-center justify-between">
              <div className="text-gray-400 text-sm mb-4 md:mb-0">
                © 2025 SecureAPK Detector. Built for Digital Rakshak Hackathon.
                All rights reserved.
              </div>
              <div className="flex items-center space-x-6 text-sm">
                <div className="flex items-center text-gray-400">
                  <HiGlobeAlt className="w-4 h-4 mr-2" />
                  Made in India
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
