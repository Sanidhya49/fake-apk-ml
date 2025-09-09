import React from "react";
import { HiShieldCheck, HiPlay, HiChip } from "react-icons/hi";
import { BsShieldFillCheck, BsRobot, BsClock } from "react-icons/bs";
import { scrollToSection } from "../../utils/scrollUtils";
import useAppStore from "../../store/useAppStore";

const HeroSection = () => {
  const { analysisResults, resetApp } = useAppStore();

  const handleDetectAppsClick = () => {
    // If results are showing, reset the app first
    if (analysisResults) {
      resetApp();
    } else {
      // If no results, just scroll to upload section
      scrollToSection("upload");
    }
  };

  return (
    <section
      id="home"
      className="relative min-h-screen flex items-center justify-center overflow-hidden bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900"
    >
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-10">
        <div className="absolute inset-0 bg-grid-pattern"></div>
        <div className="absolute inset-0 bg-gradient-to-br from-transparent via-gray-800/10 to-gray-700/10"></div>
      </div>

      {/* Floating Elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-32 h-32 bg-gradient-to-br from-accent-400/20 to-primary-400/20 rounded-full blur-xl animate-float"></div>
        <div
          className="absolute top-40 right-20 w-24 h-24 bg-gradient-to-br from-teal-400/20 to-success-400/20 rounded-full blur-xl animate-float"
          style={{ animationDelay: "1s" }}
        ></div>
        <div
          className="absolute bottom-32 left-20 w-40 h-40 bg-gradient-to-br from-primary-400/20 to-accent-400/20 rounded-full blur-xl animate-float"
          style={{ animationDelay: "2s" }}
        ></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Main Hero Content */}
        <div className="animate-fade-up">
          {/* Security Badge */}
          <div className="mt-4 inline-flex items-center px-4 py-2 rounded-full bg-gray-800/90 backdrop-blur-sm border border-primary-600/50 text-primary-400 text-sm font-medium mb-6 shadow-lg">
            <HiShieldCheck className="w-4 h-4 mr-2" />
            Real Time APK Analysis
          </div>

          {/* Main Headline */}
          <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold text-white mb-6 leading-tight">
            Protect Yourself from
            <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-400 via-teal-400 to-accent-400">
              Fake Banking Apps
            </span>
          </h1>

          {/* Subheading */}
          <p className="text-xl md:text-2xl text-gray-300 mb-8 max-w-4xl mx-auto leading-relaxed">
            An AI-powered tool that scans banking APKs in real time to detect
            malicious code, suspicious permissions, embedded trackers, and
            phishing risks — delivering rapid threat triage for security
          </p>

          {/* CTA Button */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <button
              onClick={handleDetectAppsClick}
              className="group relative inline-flex items-center px-8 py-4 bg-gradient-to-r from-primary-600 to-teal-600 hover:from-primary-700 hover:to-teal-700 text-white font-semibold rounded-xl shadow-xl hover:shadow-2xl transform hover:-translate-y-1 transition-all duration-300"
            >
              <HiPlay className="w-5 h-5 mr-2 group-hover:animate-bounce" />
              Detect Fake Banking Apps
            </button>

            <button
              onClick={() => scrollToSection("demo")}
              className="inline-flex items-center px-8 py-4 bg-gray-800/90 backdrop-blur-sm border border-gray-600/50 text-gray-200 font-semibold rounded-xl hover:bg-gray-800 transition-all duration-300 shadow-lg hover:shadow-xl"
            >
              <HiChip className="w-5 h-5 mr-2" />
              See Our System in Action
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
