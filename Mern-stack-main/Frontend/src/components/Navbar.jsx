import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { NavLink, Link } from "react-router-dom";
import { QrCode, Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";

const Navbar = () => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const closeMobileMenu = () => {
    setIsMobileMenuOpen(false);
  };

  // Lock body scroll when mobile menu is open
  useEffect(() => {
    if (isMobileMenuOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    // Cleanup on unmount
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isMobileMenuOpen]);

  const navLinkStyle = ({ isActive }) =>
    `relative text-gray-300 hover:text-white transition-colors ${
      isActive ? "font-semibold" : ""
    }`;

  const mobileNavLinkStyle = ({ isActive }) =>
    `block py-3 px-4 text-lg text-gray-300 hover:text-white hover:bg-white/10 rounded-lg transition-all ${
      isActive ? "font-semibold bg-white/5" : ""
    }`;

  return (
    <motion.nav
      initial={{ y: -100, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: "easeOut" }}
      className="fixed top-0 left-0 right-0 z-50 glass-effect"
    >
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3" onClick={closeMobileMenu}>
            <motion.div
              whileHover={{ scale: 1.05, rotate: -5 }}
              className="flex items-center gap-3"
            >
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center">
                <QrCode className="w-6 h-6 text-white" />
              </div>
              <span className="text-3xl font-bold text-gradient">Attendy</span>
            </motion.div>
          </Link>

          <div className="hidden md:flex items-center gap-8">
            <NavLink to="/features" className={navLinkStyle}>
              {({ isActive }) => (
                <>
                  <motion.span whileHover={{ y: -2 }} className="block">
                    Features
                  </motion.span>
                  {isActive && (
                    <motion.div
                      layoutId="underline"
                      className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-400 to-purple-400"
                    />
                  )}
                </>
              )}
            </NavLink>
            <NavLink to="/how-it-works" className={navLinkStyle}>
              {({ isActive }) => (
                <>
                  <motion.span whileHover={{ y: -2 }} className="block">
                    How It Works
                  </motion.span>
                  {isActive && (
                    <motion.div
                      layoutId="underline"
                      className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-400 to-purple-400"
                    />
                  )}
                </>
              )}
            </NavLink>
            <NavLink to="/about" className={navLinkStyle}>
              {({ isActive }) => (
                <>
                  <motion.span whileHover={{ y: -2 }} className="block">
                    About
                  </motion.span>
                  {isActive && (
                    <motion.div
                      layoutId="underline"
                      className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-400 to-purple-400"
                    />
                  )}
                </>
              )}
            </NavLink>
            <NavLink to="/contact" className={navLinkStyle}>
              {({ isActive }) => (
                <>
                  <motion.span whileHover={{ y: -2 }} className="block">
                    Contact
                  </motion.span>
                  {isActive && (
                    <motion.div
                      layoutId="underline"
                      className="absolute -bottom-1 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-400 to-purple-400"
                    />
                  )}
                </>
              )}
            </NavLink>
            <Link to="/login">
              <Button className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 transform hover:scale-105 transition-transform text-white">
                Get Started
              </Button>
            </Link>
          </div>

          <Button
            variant="ghost"
            size="icon"
            onClick={toggleMobileMenu}
            className="md:hidden text-white hover:bg-white/10"
          >
            {isMobileMenuOpen ? (
              <X className="w-6 h-6" />
            ) : (
              <Menu className="w-6 h-6" />
            )}
          </Button>
        </div>

        {/* Mobile Menu */}
        <AnimatePresence>
          {isMobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
              className="md:hidden mt-4 pb-4 overflow-hidden rounded-xl bg-gradient-to-br from-blue-900/95 to-purple-900/95 backdrop-blur-lg border border-white/10 shadow-2xl"
            >
              <div className="flex flex-col space-y-2 p-2">
                <NavLink
                  to="/features"
                  className={mobileNavLinkStyle}
                  onClick={closeMobileMenu}
                >
                  Features
                </NavLink>
                <NavLink
                  to="/how-it-works"
                  className={mobileNavLinkStyle}
                  onClick={closeMobileMenu}
                >
                  How It Works
                </NavLink>
                <NavLink
                  to="/about"
                  className={mobileNavLinkStyle}
                  onClick={closeMobileMenu}
                >
                  About
                </NavLink>
                <NavLink
                  to="/contact"
                  className={mobileNavLinkStyle}
                  onClick={closeMobileMenu}
                >
                  Contact
                </NavLink>
                <Link to="/login" onClick={closeMobileMenu}>
                  <Button className="w-full mt-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white">
                    Get Started
                  </Button>
                </Link>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.nav>
  );
};

export default Navbar;
