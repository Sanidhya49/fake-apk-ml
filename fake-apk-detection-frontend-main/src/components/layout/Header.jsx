import React from "react";
import { HiShieldCheck } from "react-icons/hi";

const Header = () => {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-gray-900/90 backdrop-blur-md border-b border-gray-700/30">
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 md:h-20">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-teal-500 shadow-lg">
              <HiShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div className="flex flex-col">
              <h1 className="text-xl md:text-2xl font-bold text-white">
                SecureAPK
                <span className="text-primary-400 ml-1">Detector</span>
              </h1>
              <p className="text-xs text-gray-400 hidden md:block">
                Digital Rakshak
              </p>
            </div>
          </div>
        </div>
      </nav>
    </header>
  );
};

export default Header;
