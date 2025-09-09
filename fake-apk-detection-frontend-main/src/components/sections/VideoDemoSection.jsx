import React from "react";
import { HiPlay, HiEye } from "react-icons/hi";
import { BsPlayCircle, BsShieldCheck } from "react-icons/bs";

const VideoDemoSection = () => {
  return (
    <section id="demo" className="relative overflow-hidden">
      {/* Header Section - matching HeroSection gradient style */}
      <div className="bg-gradient-to-br from-gray-50 via-blue-50 to-teal-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 py-16 md:py-20 relative">
        {/* Background Pattern */}
        <div className="absolute inset-0 opacity-30 dark:opacity-10">
          <div className="absolute inset-0 bg-grid-pattern"></div>
        </div>

        {/* Floating Elements */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-20 right-10 w-32 h-32 bg-gradient-to-br from-primary-400/15 to-teal-400/15 rounded-full blur-xl animate-float"></div>
          <div
            className="absolute bottom-20 left-10 w-40 h-40 bg-gradient-to-br from-accent-400/15 to-success-400/15 rounded-full blur-xl animate-float"
            style={{ animationDelay: "1.5s" }}
          ></div>
        </div>

        <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Section Header */}
          <div className="text-center mb-12 animate-fade-up">
            <div className="inline-flex items-center px-4 py-2 rounded-full bg-white/90 dark:bg-gray-800/90 backdrop-blur-sm border border-primary-200/50 dark:border-primary-600/50 text-primary-400 text-sm font-medium mb-6 shadow-lg">
              <BsPlayCircle className="w-4 h-4 mr-2" />
              Live Demo
            </div>

            <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-white mb-4">
              See Our System in
              <span className="block text-transparent bg-clip-text bg-gradient-to-r from-primary-600 via-teal-600 to-accent-600 dark:from-primary-400 dark:via-teal-400 dark:to-accent-400">
                Action
              </span>
            </h2>

            <p className="text-xl text-gray-300 max-w-3xl mx-auto leading-relaxed">
              Watch how our AI-powered fake APK detection system analyzes
              banking applications and identifies security threats in real-time
            </p>
          </div>
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Video Container */}
          <div
            className="max-w-5xl mx-auto animate-fade-up"
            style={{ animationDelay: "200ms" }}
          >
            <div className="relative">
              {/* Video Frame with Enhanced Styling */}
              <div className="relative rounded-2xl overflow-hidden bg-gray-100 dark:bg-gray-800 p-2 shadow-2xl border border-gray-700/50">
                <div className="relative rounded-xl overflow-hidden bg-black">
                  <iframe
                    width="100%"
                    height="500"
                    src="https://www.youtube.com/embed/qRZirgZuICc"
                    title="Fake APK Detection System Demo"
                    frameBorder="0"
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
                    referrerPolicy="strict-origin-when-cross-origin"
                    allowFullScreen
                    className="w-full aspect-video"
                  ></iframe>
                </div>
              </div>

              {/* Decorative Elements */}
              <div className="absolute -top-6 -left-6 w-12 h-12 bg-gradient-to-br from-primary-500 to-teal-500 rounded-full opacity-20 animate-pulse"></div>
              <div
                className="absolute -bottom-6 -right-6 w-16 h-16 bg-gradient-to-br from-accent-500 to-success-500 rounded-full opacity-20 animate-pulse"
                style={{ animationDelay: "1s" }}
              ></div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default VideoDemoSection;

