import { useState, useEffect, useRef } from 'react';
import { CommandProcessor } from './CommandProcessor';

interface TerminalLine {
  id: string;
  content: string;
  type: 'system' | 'user' | 'output' | 'error' | 'success' | 'warning';
  timestamp?: string;
}

export const Terminal = () => {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [currentInput, setCurrentInput] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [showBanner, setShowBanner] = useState(true);
  const terminalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const addLine = (content: string, type: TerminalLine['type'] = 'output') => {
    const newLine: TerminalLine = {
      id: Date.now().toString(),
      content,
      type,
      timestamp: new Date().toLocaleTimeString()
    };
    setLines(prev => [...prev, newLine]);
  };

  const addLines = (newLines: TerminalLine[]) => {
    setLines(prev => [...prev, ...newLines]);
  };

  const initializeTerminal = async () => {
    const initLines: TerminalLine[] = [
      { id: '1', content: 'Initializing Neural Security Core... ONLINE', type: 'system' },
      { id: '2', content: 'Loading Exploit Database... SYNCED', type: 'system' },
      { id: '3', content: 'Mapping Threat Vectors... ACTIVE', type: 'system' },
      { id: '4', content: '', type: 'output' },
      { id: '5', content: `[SYSTEM] Welcome, Operator. Authentication bypassed. Time: ${new Date().toLocaleTimeString()}.`, type: 'success' },
      { id: '6', content: "[SYSTEM] Enter a command or type 'help' to list available modules.", type: 'system' },
      { id: '7', content: '', type: 'output' },
    ];

    for (let i = 0; i < initLines.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 500));
      setLines(prev => [...prev, initLines[i]]);
    }
    setShowBanner(false);
  };

  useEffect(() => {
    if (showBanner) {
      initializeTerminal();
    }
  }, [showBanner]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [lines]);

  useEffect(() => {
    if (inputRef.current && !isProcessing) {
      inputRef.current.focus();
    }
  }, [isProcessing]);

  const handleCommand = async (command: string) => {
    if (!command.trim()) return;

    addLine(`shadowfall> ${command}`, 'user');
    setCurrentInput('');
    setIsProcessing(true);

    try {
      await CommandProcessor.processCommand(command, addLine, addLines);
    } catch (error) {
      addLine(`[ERROR] Command failed: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
    }

    setIsProcessing(false);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !isProcessing) {
      handleCommand(currentInput);
    }
  };

  const getLineClassName = (type: TerminalLine['type']) => {
    const baseClass = 'font-mono text-sm leading-relaxed';
    switch (type) {
      case 'system':
        return `${baseClass} text-terminal-accent`;
      case 'user':
        return `${baseClass} text-terminal-text`;
      case 'output':
        return `${baseClass} text-terminal-text`;
      case 'error':
        return `${baseClass} text-terminal-error`;
      case 'success':
        return `${baseClass} text-terminal-success`;
      case 'warning':
        return `${baseClass} text-terminal-warning`;
      default:
        return `${baseClass} text-terminal-text`;
    }
  };

  const asciiArt = `
    ██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗
    ██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝
    ██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║   
    ██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║   
    ██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║   
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   
                                                              
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ █████╗ ██╗     ██╗     
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██║     ██║     
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╗  ███████║██║     ██║     
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══╝  ██╔══██║██║     ██║     
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║     ██║  ██║███████╗███████╗
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
  `;

  return (
    <div className="min-h-screen bg-terminal font-mono">
      <div className="container mx-auto p-4 h-screen flex flex-col">
        {showBanner && (
          <div className="flex items-center justify-center mb-8">
            <pre className="text-terminal-glow text-xs sm:text-sm animate-pulse-glow whitespace-pre-wrap">
              {asciiArt}
            </pre>
          </div>
        )}
        
        <div 
          ref={terminalRef}
          className="flex-1 overflow-y-auto bg-terminal border border-terminal-glow rounded-lg p-4 shadow-terminal"
          style={{ backgroundColor: 'rgba(0, 0, 0, 0.9)' }}
        >
          {lines.map((line) => (
            <div key={line.id} className={getLineClassName(line.type)}>
              {line.content || '\u00A0'}
            </div>
          ))}
          
          {!isProcessing && !showBanner && (
            <div className="flex items-center mt-2">
              <span className="text-terminal-glow mr-2">shadowfall&gt;</span>
              <input
                ref={inputRef}
                type="text"
                value={currentInput}
                onChange={(e) => setCurrentInput(e.target.value)}
                onKeyPress={handleKeyPress}
                className="flex-1 bg-transparent border-none outline-none text-terminal-text font-mono text-sm caret-terminal-glow"
                disabled={isProcessing}
                placeholder="Enter command..."
              />
              <span className="animate-blink-caret border-r-2 border-terminal-glow h-4 ml-1"></span>
            </div>
          )}
          
          {isProcessing && (
            <div className="flex items-center mt-2">
              <span className="text-terminal-accent animate-pulse">Processing...</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};