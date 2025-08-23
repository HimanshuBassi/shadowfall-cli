import { useLocation } from "react-router-dom";
import { useEffect } from "react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-terminal">
      <div className="text-center font-mono">
        <div className="text-6xl font-bold mb-4 text-terminal-error animate-pulse-glow">404</div>
        <div className="text-xl text-terminal-text mb-4">[ERROR] Neural pathway not found</div>
        <div className="text-terminal-accent mb-8">The requested module does not exist in the Shadowfall database.</div>
        <a 
          href="/" 
          className="text-terminal-glow hover:text-terminal-accent underline transition-colors duration-200"
        >
          [RETURN] Back to Terminal
        </a>
      </div>
    </div>
  );
};

export default NotFound;
