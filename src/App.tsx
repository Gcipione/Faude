/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { createClient } from '@supabase/supabase-js';
import Tesseract from 'tesseract.js';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  History, 
  LayoutDashboard, 
  LogOut, 
  Link as LinkIcon, 
  MessageSquare, 
  Image as ImageIcon, 
  AlertTriangle,
  Loader2,
  ChevronRight,
  User,
  Lock,
  Mail,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  XCircle,
  FileText,
  Scan,
  Trash2
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

import { GoogleGenAI } from "@google/genai";

// --- Supabase Configuration ---
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

// Check if configuration is missing
const isConfigMissing = !supabaseUrl || !supabaseAnonKey || supabaseUrl.includes('your-project-id');

const supabase = createClient(supabaseUrl, supabaseAnonKey);

// --- Gemini AI Configuration ---
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });

// --- Types ---
type ScanStatus = 'safe' | 'suspicious' | 'danger';

const performDeepScan = async (content: string, type: 'url' | 'text' | 'image', imageData?: string | null) => {
  try {
    const parts: any[] = [
      { text: `Analise se este conteúdo é um golpe de phishing ou fraude. 
      ${type === 'image' ? 'Analise a imagem em anexo e o texto extraído dela: ' : 'Conteúdo: '}"${content}". 
      Verifique se o domínio é oficial, se há relatos de fraude e se os padrões de comunicação são suspeitos.
      Retorne um JSON com:
      {
        "score": number (0-100),
        "status": "safe" | "suspicious" | "danger",
        "details": string[],
        "isOfficial": boolean,
        "reasoning": string
      }` }
    ];

    if (type === 'image' && imageData) {
      const base64Data = imageData.includes('base64,') ? imageData.split('base64,')[1] : imageData;
      parts.push({
        inlineData: {
          mimeType: "image/jpeg",
          data: base64Data
        }
      });
    }

    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: { parts },
      config: {
        tools: [{ googleSearch: {} }],
        responseMimeType: "application/json",
      },
    });

    const result = JSON.parse(response.text || '{}');
    return result;
  } catch (error) {
    console.error("Deep Scan Error:", error);
    return null;
  }
};

interface ScanRecord {
  id: string;
  user_id: string;
  content: string;
  score: number;
  status: ScanStatus;
  created_at: string;
  type: 'url' | 'text' | 'image';
}

// --- Detection Logic ---
const OFFICIAL_BANKS = ['itau', 'bradesco', 'santander', 'bb', 'caixa', 'nubank', 'inter', 'pagbank', 'c6bank', 'btgpactual'];

const OFFICIAL_BANK_SITES = [
  {
    name: 'Itaú Unibanco',
    domain: 'itau.com.br',
    sublinks: ['/login', '/internet-banking', '/ajuda', '/seguranca'],
    color: '#EC7000'
  },
  {
    name: 'Bradesco',
    domain: 'bradesco.com.br',
    sublinks: ['/login', '/internet-banking', '/seguranca', '/atendimento'],
    color: '#CC092F'
  },
  {
    name: 'Santander',
    domain: 'santander.com.br',
    sublinks: ['/login', '/internet-banking', '/seguranca', '/contato'],
    color: '#EC0000'
  },
  {
    name: 'Banco do Brasil',
    domain: 'bb.com.br',
    sublinks: ['/login', '/internet-banking', '/seguranca', '/atendimento'],
    color: '#FCF100'
  },
  {
    name: 'Caixa Econômica',
    domain: 'caixa.gov.br',
    sublinks: ['/login', '/internet-banking', '/seguranca', '/atendimento'],
    color: '#005CA9'
  },
  {
    name: 'Nubank',
    domain: 'nubank.com.br',
    sublinks: ['/login', '/seguranca', '/contato'],
    color: '#8A05BE'
  },
  {
    name: 'Banco Inter',
    domain: 'bancointer.com.br',
    sublinks: ['/login', '/seguranca', '/atendimento'],
    color: '#FF7A00'
  }
];
const SUSPICIOUS_WORDS = ['urgente', 'bloqueado', 'senha', 'cpf', 'verifique', 'atualize', 'seguranca', 'token', 'confirmar', 'imediatamente', 'expira', 'vencimento', 'irregularidade'];
const THREAT_WORDS = ['bloqueio', 'cancelamento', 'multa', 'processo', 'judicial', 'suspenso', 'limite', 'excedido'];

// --- Components ---

export default function App() {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<'auth' | 'dashboard' | 'scan' | 'history' | 'official_sites'>('auth');
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login');
  
  // Auth State
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [officialSearch, setOfficialSearch] = useState('');
  const [customSites, setCustomSites] = useState<any[]>([]);
  const [isAddingSite, setIsAddingSite] = useState(false);
  const [newSite, setNewSite] = useState({ name: '', domain: '', sublinks: '', color: '#d4af37', domain_age: '' });

  // Scan State
  const [scanType, setScanType] = useState<'url' | 'text' | 'image'>('url');
  const [input, setInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [stats, setStats] = useState({ total: 0, danger: 0, suspicious: 0, safe: 0 });
  const [imageBase64, setImageBase64] = useState<string | null>(null);

  const analyzeContent = (content: string, type: 'url' | 'text' | 'image'): { score: number; status: ScanStatus; details: string[] } => {
    let score = 0;
    const details: string[] = [];
    const lowerContent = content.toLowerCase();
    const allSites = [...OFFICIAL_BANK_SITES, ...customSites];

    if (type === 'url') {
      // 1. HTTPS Check
      if (!lowerContent.startsWith('https://')) {
        score += 20;
        details.push('Conexão não segura (sem HTTPS)');
      }

      // 2. IP in Domain
      const ipRegex = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
      if (ipRegex.test(lowerContent)) {
        score += 40;
        details.push('Endereço IP detectado no domínio');
      }

      // 3. Typosquatting (simplified)
      const typos = ['banc0', 'g00gle', 'itau-', 'bradesc0', 'nubank-', 'caixa-'];
      if (typos.some(t => lowerContent.includes(t))) {
        score += 40;
        details.push('Possível domínio falso (typosquatting)');
      }

      // 4. Excessive Subdomains
      const parts = lowerContent.replace('https://', '').replace('http://', '').split('/')[0].split('.');
      if (parts.length > 3) {
        score += 25;
        details.push('Excesso de subdomínios detectado');
      }

      // 5. Suspicious Words in URL
      SUSPICIOUS_WORDS.forEach(word => {
        if (lowerContent.includes(word)) {
          score += 15;
          details.push(`Palavra suspeita na URL: ${word}`);
        }
      });

      // 6. Bank Comparison (Improved)
      const domain = lowerContent.replace('https://', '').replace('http://', '').split('/')[0];
      const hasBankName = OFFICIAL_BANKS.some(bank => domain.includes(bank));
      
      // Check against official directory
      const officialBank = allSites.find(bank => 
        domain === bank.domain || domain.endsWith(`.${bank.domain}`)
      );

      if (officialBank) {
        // It's a match for an official domain
        score = 0; // Reset score if it's official
        details.push(`Domínio oficial confirmado: ${officialBank.name}`);
        
        // Check if the sublink is common (optional but good for UX)
        const path = lowerContent.replace(`https://${domain}`, '').replace(`http://${domain}`, '');
        if (path && path !== '/' && !officialBank.sublinks.some((sub: string) => path.startsWith(sub))) {
          details.push('Aviso: O caminho acessado não é um dos links comuns, mas o domínio é legítimo.');
        }
      } else if (hasBankName) {
        score += 45;
        details.push('ALERTA CRÍTICO: Usa nome de banco em um domínio NÃO oficial');
      }
    } else {
      // Text/Image Analysis (Social Engineering)
      
      // 1. Urgency
      const urgencyWords = ['agora', 'imediatamente', 'urgente', 'expira', '24h', 'hoje'];
      urgencyWords.forEach(word => {
        if (lowerContent.includes(word)) {
          score += 25;
          details.push(`Padrão de urgência detectado: "${word}"`);
        }
      });

      // 2. Threat
      THREAT_WORDS.forEach(word => {
        if (lowerContent.includes(word)) {
          score += 25;
          details.push(`Padrão de ameaça detectado: "${word}"`);
        }
      });

      // 3. Data Request
      const dataWords = ['senha', 'token', 'cpf', 'dados', 'confirmar', 'acesso'];
      dataWords.forEach(word => {
        if (lowerContent.includes(word)) {
          score += 30;
          details.push(`Solicitação de dados sensíveis: "${word}"`);
        }
      });

      // 4. Links in text
      if (lowerContent.includes('http://') || lowerContent.includes('https://') || lowerContent.includes('bit.ly') || lowerContent.includes('t.me')) {
        score += 20;
        details.push('Link externo detectado na mensagem');
      }
    }

    // Final Classification
    score = Math.min(score, 100);
    let status: ScanStatus = 'safe';
    if (score > 70) status = 'danger';
    else if (score > 30) status = 'suspicious';

    return { score, status, details };
  };

  const audioRef = useRef<HTMLAudioElement | null>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
      if (session?.user) setView('dashboard');
      setLoading(false);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
      if (session?.user) setView('dashboard');
      else setView('auth');
    });

    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!user) return;

    // Initial fetch
    fetchScans();
    fetchCustomSites();

    // Real-time subscription for scans
    const scansSubscription = supabase
      .channel('scans-changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'scans',
          filter: `user_id=eq.${user.id}`
        },
        () => {
          console.log('Real-time update: scans changed');
          fetchScans();
        }
      )
      .subscribe();

    // Real-time subscription for official_sites
    const sitesSubscription = supabase
      .channel('sites-changes')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'official_sites'
        },
        () => {
          console.log('Real-time update: official_sites changed');
          fetchCustomSites();
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(scansSubscription);
      supabase.removeChannel(sitesSubscription);
    };
  }, [user]);

  const [dbStatus, setDbStatus] = useState<'checking' | 'online' | 'offline'>('checking');

  useEffect(() => {
    const checkConnection = async () => {
      try {
        const { error } = await supabase.from('official_sites').select('id').limit(1);
        if (error) throw error;
        setDbStatus('online');
      } catch (err) {
        console.error('Connection check failed:', err);
        setDbStatus('offline');
      }
    };
    if (user) checkConnection();
  }, [user]);

  const fetchCustomSites = async () => {
    console.log('Fetching custom sites...');
    const { data, error } = await supabase
      .from('official_sites')
      .select('*')
      .order('name', { ascending: true });
    
    if (!error && data) {
      console.log('Custom sites fetched:', data.length);
      setCustomSites(data);
    } else if (error) {
      console.error('Error fetching custom sites:', error);
    }
  };

  const fetchScans = async () => {
    if (!user) return;
    console.log('Fetching scans for user:', user.id);
    const { data, error } = await supabase
      .from('scans')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (!error && data) {
      console.log('Scans fetched successfully:', data.length, 'records');
      setScans(data);
      const newStats = data.reduce((acc, curr) => {
        acc.total++;
        if (curr.status === 'danger') acc.danger++;
        else if (curr.status === 'suspicious') acc.suspicious++;
        else if (curr.status === 'safe') acc.safe++;
        return acc;
      }, { total: 0, danger: 0, suspicious: 0, safe: 0 });
      setStats(newStats);
    } else if (error) {
      console.error('Error fetching scans:', error);
    }
  };

  const handleAddSite = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('Attempting to add site...', newSite);
    
    if (!user) {
      alert('Você precisa estar logado para cadastrar instituições.');
      return;
    }

    if (!newSite.name || !newSite.domain) {
      alert('Nome e Domínio são obrigatórios.');
      return;
    }

    const siteData: any = {
      user_id: user.id,
      name: newSite.name,
      domain: newSite.domain.toLowerCase().replace('https://', '').replace('http://', '').split('/')[0],
      sublinks: newSite.sublinks.split(',').map(s => s.trim()).filter(s => s),
      color: newSite.color
    };

    // Try to include domain_age if it exists
    if (newSite.domain_age) {
      siteData.domain_age = newSite.domain_age;
    }

    console.log('Saving site data to Supabase:', siteData);
    const { error } = await supabase.from('official_sites').insert([siteData]);
    
    if (error) {
      console.error('Error adding site:', error);
      const errorMessage = error.message || '';
      // If domain_age column doesn't exist, try without it
      if (errorMessage.includes('column "domain_age"')) {
        console.log('Retrying without domain_age column...');
        const siteDataRetry = { ...siteData };
        delete siteDataRetry.domain_age;
        const { error: retryError } = await supabase.from('official_sites').insert([siteDataRetry]);
        if (retryError) {
          alert(`Erro ao adicionar site: ${retryError.message}`);
        } else {
          setIsAddingSite(false);
          setNewSite({ name: '', domain: '', sublinks: '', color: '#d4af37', domain_age: '' });
        }
      } else {
        alert(`Erro ao adicionar site: ${errorMessage}`);
      }
    } else {
      console.log('Site added successfully');
      setIsAddingSite(false);
      setNewSite({ name: '', domain: '', sublinks: '', color: '#d4af37', domain_age: '' });
      // fetchCustomSites() will be called by the real-time subscription
    }
  };

  const handleDeleteSite = async (id: string) => {
    console.log('Deleting site:', id);
    const { error } = await supabase.from('official_sites').delete().eq('id', id);
    if (error) {
      console.error('Error deleting site:', error);
      alert(`Erro ao excluir site: ${error.message}`);
    } else {
      console.log('Site deleted successfully');
      // fetchCustomSites() will be called by the real-time subscription
    }
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    setLoading(true);

    try {
      if (authMode === 'login') {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
      } else {
        const { error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        alert('Verifique seu email para confirmar o cadastro!');
      }
    } catch (err: any) {
      setAuthError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await supabase.auth.signOut();
    setView('auth');
  };

  const playAlert = () => {
    if (!audioRef.current) {
      audioRef.current = new Audio('https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3');
    }
    audioRef.current.play().catch(() => {});
  };

  const [isDeepScanning, setIsDeepScanning] = useState(false);

  const [isFetchingLinks, setIsFetchingLinks] = useState(false);

  const fetchOfficialLinks = async () => {
    if (!newSite.domain) return;
    setIsFetchingLinks(true);
    try {
      const aiInstance = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });
      const response = await aiInstance.models.generateContent({
        model: "gemini-3-flash-preview",
        contents: `Pesquise os sublinks oficiais mais comuns (como /login, /carrinho, /seguranca) e a data de criação ou tempo de existência do domínio: ${newSite.domain}. 
        Retorne um JSON com:
        {
          "sublinks": string[],
          "domainAge": string (ex: "15 anos", "Criado em 2005"),
          "description": string
        }`,
        config: {
          tools: [{ googleSearch: {} }],
          responseMimeType: "application/json",
        },
      });

      let data;
      try {
        data = JSON.parse(response.text || '{}');
      } catch (e) {
        console.error("Failed to parse AI response:", e);
        // Fallback to simple parsing if JSON fails
        const text = response.text || '';
        setNewSite(prev => ({ ...prev, sublinks: text }));
        return;
      }

      if (data && data.sublinks) {
        setNewSite(prev => ({
          ...prev,
          sublinks: data.sublinks.join(', '),
          domain_age: data.domainAge || ''
        }));
      }
    } catch (error) {
      console.error("Error fetching links:", error);
    } finally {
      setIsFetchingLinks(false);
    }
  };

  const performScan = async (isDeep: boolean = false) => {
    if (!user) {
      console.error("User not found for scan");
      return;
    }
    if (!input && scanType !== 'image') return;
    
    if (isDeep) setIsDeepScanning(true);
    else setIsScanning(true);
    
    setScanResult(null);

    let contentToAnalyze = input;

    try {
      let result;
      if (isDeep) {
        result = await performDeepScan(contentToAnalyze, scanType, imageBase64);
      } else {
        result = analyzeContent(contentToAnalyze, scanType);
      }
      
      if (!result) {
        alert("Falha na análise. Verifique sua conexão ou tente novamente.");
        throw new Error("Falha na análise");
      }

      if (result.status === 'danger') {
        playAlert();
      }

      const scanData = {
        user_id: user.id,
        content: contentToAnalyze,
        score: result.score,
        status: result.status,
        type: scanType
      };

      console.log('Saving scan data to Supabase:', scanData);
      const { data: savedData, error } = await supabase.from('scans').insert([scanData]).select();
      
      if (error) {
        console.error('Error saving scan to Supabase:', error);
        // Fallback: show result even if save fails
        setScanResult({ ...result, content: contentToAnalyze, isDeep });
      } else {
        console.log('Scan saved successfully:', savedData);
        setScanResult({ ...result, content: contentToAnalyze, isDeep });
        
        // Update local state immediately for instant feedback
        if (savedData && savedData[0]) {
          setScans(prev => [savedData[0], ...prev]);
        }
        
        // Refresh stats and full list
        await fetchScans();
      }
    } catch (err) {
      console.error('Scan failed:', err);
    } finally {
      setIsScanning(false);
      setIsDeepScanning(false);
    }
  };

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsScanning(true);
    setScanResult(null);
    
    // Convert to base64 for Gemini
    const reader = new FileReader();
    reader.onloadend = async () => {
      const base64 = reader.result as string;
      setImageBase64(base64);
      
      try {
        const result = await Tesseract.recognize(file, 'por+eng', {
          logger: m => console.log(m)
        });
        const extractedText = result.data.text;
        setInput(extractedText);
        setScanType('image');
        
        // Auto-scan after OCR
        const analysis = analyzeContent(extractedText, 'image');
        if (analysis.status === 'danger') playAlert();
        
        const scanData = {
          user_id: user.id,
          content: extractedText,
          score: analysis.score,
          status: analysis.status,
          type: 'image'
        };

        console.log('Saving image scan data to Supabase:', scanData);
        const { data: savedData, error } = await supabase.from('scans').insert([scanData]).select();
        
        if (error) {
          console.error('Error saving image scan to Supabase:', error);
          setScanResult({ ...analysis, content: extractedText });
        } else {
          console.log('Image scan saved successfully:', savedData);
          setScanResult({ ...analysis, content: extractedText });
          
          // Update local state immediately
          if (savedData && savedData[0]) {
            setScans(prev => [savedData[0], ...prev]);
          }
          
          await fetchScans();
        }
      } catch (err) {
        console.error('OCR Error:', err);
      } finally {
        setIsScanning(false);
      }
    };
    reader.readAsDataURL(file);
  };

  if (loading && !user) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="w-12 h-12 text-gold animate-spin" />
      </div>
    );
  }

  if (isConfigMissing) {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <motion.div 
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass-panel w-full max-w-lg p-8 text-center border-red-500/30"
        >
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-6" />
          <h1 className="text-2xl font-bold text-white mb-4">Configuração Necessária</h1>
          <p className="text-gray-400 mb-8">
            Para o sistema <span className="text-gold font-bold">ShieldBank BLACK</span> funcionar, você precisa configurar as chaves do Supabase.
          </p>
          
          <div className="bg-bank-black/50 p-6 rounded-xl text-left space-y-4 border border-gold/10 mb-8">
            <p className="text-sm text-gray-300 font-mono">1. Vá em <span className="text-gold">Settings &gt; Secrets</span></p>
            <p className="text-sm text-gray-300 font-mono">2. Adicione <span className="text-gold">VITE_SUPABASE_URL</span></p>
            <p className="text-sm text-gray-300 font-mono">3. Adicione <span className="text-gold">VITE_SUPABASE_ANON_KEY</span></p>
          </div>

          <p className="text-xs text-gray-500">Após adicionar, a página irá recarregar automaticamente.</p>
        </motion.div>
      </div>
    );
  }

  if (view === 'auth') {
    return (
      <div className="flex items-center justify-center min-h-screen p-4">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-panel w-full max-w-md p-8 gold-glow"
        >
          <div className="flex flex-col items-center mb-8">
            <div className="w-16 h-16 bg-gradient-to-br from-gold to-gold-light rounded-2xl flex items-center justify-center mb-4 shadow-[0_0_30px_rgba(212,175,55,0.3)]">
              <Shield className="w-10 h-10 text-bank-black" />
            </div>
            <h1 className="text-3xl font-bold gold-text-gradient tracking-tighter">ShieldBank BLACK</h1>
            <p className="text-gray-400 text-sm mt-2">Segurança de elite para seus ativos digitais</p>
          </div>

          <form onSubmit={handleAuth} className="space-y-4">
            <div className="relative">
              <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gold/50" />
              <input 
                type="email" 
                placeholder="Seu email" 
                className="input-field w-full pl-12"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="relative">
              <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gold/50" />
              <input 
                type="password" 
                placeholder="Sua senha" 
                className="input-field w-full pl-12"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            {authError && (
              <div className="bg-red-500/10 border border-red-500/50 text-red-500 text-sm p-3 rounded-xl flex items-center gap-2">
                <AlertCircle className="w-4 h-4" />
                {authError}
              </div>
            )}

            <button type="submit" className="btn-gold w-full mt-4" disabled={loading}>
              {loading ? <Loader2 className="w-5 h-5 animate-spin mx-auto" /> : (authMode === 'login' ? 'Acessar Sistema' : 'Criar Conta Premium')}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button 
              onClick={() => setAuthMode(authMode === 'login' ? 'signup' : 'login')}
              className="text-gold/70 hover:text-gold text-sm transition-colors"
            >
              {authMode === 'login' ? 'Não tem conta? Associe-se agora' : 'Já é membro? Faça login'}
            </button>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col md:flex-row">
      {/* Sidebar */}
      <aside className="w-full md:w-64 bg-bank-dark/50 border-r border-gold/10 p-6 flex flex-col">
        <div className="flex items-center gap-3 mb-12">
          <Shield className="w-8 h-8 text-gold" />
          <span className="text-xl font-bold gold-text-gradient tracking-tighter">ShieldBank</span>
        </div>

        <nav className="flex-1 space-y-2">
          <button 
            onClick={() => setView('dashboard')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${view === 'dashboard' ? 'bg-gold text-bank-black font-bold' : 'text-gray-400 hover:bg-gold/10 hover:text-gold'}`}
          >
            <LayoutDashboard className="w-5 h-5" />
            Dashboard
          </button>
          <button 
            onClick={() => setView('scan')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${view === 'scan' ? 'bg-gold text-bank-black font-bold' : 'text-gray-400 hover:bg-gold/10 hover:text-gold'}`}
          >
            <Scan className="w-5 h-5" />
            Nova Análise
          </button>
          <button 
            onClick={() => setView('history')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${view === 'history' ? 'bg-gold text-bank-black font-bold' : 'text-gray-400 hover:bg-gold/10 hover:text-gold'}`}
          >
            <History className="w-5 h-5" />
            Histórico
          </button>
          <button 
            onClick={() => setView('official_sites')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${view === 'official_sites' ? 'bg-gold text-bank-black font-bold' : 'text-gray-400 hover:bg-gold/10 hover:text-gold'}`}
          >
            <ShieldCheck className="w-5 h-5" />
            Sites Oficiais
          </button>
        </nav>

        <div className="pt-6 border-t border-gold/10">
          <div className="flex items-center gap-3 px-4 py-3 mb-4">
            <div className="w-8 h-8 bg-gold/20 rounded-full flex items-center justify-center">
              <User className="w-4 h-4 text-gold" />
            </div>
            <div className="overflow-hidden">
              <p className="text-xs text-gray-400 truncate">{user?.email}</p>
              <p className="text-[10px] text-gold font-bold uppercase tracking-widest">Membro Black</p>
            </div>
          </div>
          <button 
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-red-400 hover:bg-red-500/10 transition-all"
          >
            <LogOut className="w-5 h-5" />
            Sair
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 md:p-10 overflow-y-auto">
        <AnimatePresence mode="wait">
          {view === 'dashboard' && (
            <motion.div 
              key="dashboard"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-8"
            >
              <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-3xl font-bold text-white">Bem-vindo, <span className="gold-text-gradient">Operador</span></h2>
                  <p className="text-gray-400">Visão geral da sua proteção digital.</p>
                </div>
                <div className="flex items-center gap-3">
                  <button 
                    onClick={() => fetchScans()} 
                    className="p-3 bg-gold/10 text-gold rounded-xl hover:bg-gold/20 transition-all"
                    title="Atualizar Dados"
                  >
                    <TrendingUp className="w-5 h-5" />
                  </button>
                  <button onClick={() => setView('scan')} className="btn-gold flex items-center gap-2">
                    <Scan className="w-5 h-5" />
                    Iniciar Nova Varredura
                  </button>
                </div>
              </header>

              {/* System Health Check */}
              <div className="glass-panel p-6 border-l-4 border-l-blue-500">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-500/10 rounded-lg">
                      <ShieldCheck className="w-6 h-6 text-blue-500" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white">Status do Sistema</h3>
                      <p className="text-xs text-gray-400">Verificação de conectividade e serviços.</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => {
                        setDbStatus('checking');
                        // Trigger re-check via effect by toggling a dummy state if needed, 
                        // or just call the check function if I expose it.
                        // For now, let's just re-fetch everything.
                        fetchScans();
                        fetchCustomSites();
                      }}
                      className="p-1.5 bg-gold/10 text-gold rounded-md hover:bg-gold/20 transition-all"
                      title="Reverificar"
                    >
                      <TrendingUp className="w-3 h-3" />
                    </button>
                    <div className="flex gap-2">
                      <div className="flex items-center gap-1 px-2 py-1 bg-green-500/10 rounded-md">
                        <div className={`w-2 h-2 rounded-full animate-pulse ${dbStatus === 'online' ? 'bg-green-500' : dbStatus === 'offline' ? 'bg-red-500' : 'bg-amber-500'}`} />
                        <span className={`text-[10px] font-bold uppercase ${dbStatus === 'online' ? 'text-green-500' : dbStatus === 'offline' ? 'text-red-500' : 'text-amber-500'}`}>
                          {dbStatus === 'online' ? 'Banco de Dados' : dbStatus === 'offline' ? 'Erro de Conexão' : 'Verificando...'}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 px-2 py-1 bg-green-500/10 rounded-md">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                        <span className="text-[10px] text-green-500 font-bold uppercase">IA Ativa</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                  <div className="p-3 bg-bank-black/50 rounded-xl border border-gold/5">
                    <p className="text-[10px] text-gray-500 uppercase font-bold">Sincronização</p>
                    <p className="text-sm text-white font-mono mt-1">Tempo Real Ativo</p>
                  </div>
                  <div className="p-3 bg-bank-black/50 rounded-xl border border-gold/5">
                    <p className="text-[10px] text-gray-500 uppercase font-bold">Sessão</p>
                    <p className="text-sm text-white font-mono mt-1">Autenticado</p>
                  </div>
                  <div className="p-3 bg-bank-black/50 rounded-xl border border-gold/5">
                    <p className="text-[10px] text-gray-500 uppercase font-bold">Proteção</p>
                    <p className="text-sm text-white font-mono mt-1">Nível Black Ativo</p>
                  </div>
                </div>
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="glass-panel p-6 border-l-4 border-l-gold">
                  <div className="flex justify-between items-start mb-4">
                    <div className="p-2 bg-gold/10 rounded-lg">
                      <TrendingUp className="w-6 h-6 text-gold" />
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">Total de Análises</p>
                  <h3 className="text-3xl font-bold text-white mt-1">{stats.total}</h3>
                </div>
                <div className="glass-panel p-6 border-l-4 border-l-red-500">
                  <div className="flex justify-between items-start mb-4">
                    <div className="p-2 bg-red-500/10 rounded-lg">
                      <ShieldAlert className="w-6 h-6 text-red-500" />
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">Golpes Detectados</p>
                  <h3 className="text-3xl font-bold text-white mt-1">{stats.danger}</h3>
                </div>
                <div className="glass-panel p-6 border-l-4 border-l-amber-500">
                  <div className="flex justify-between items-start mb-4">
                    <div className="p-2 bg-amber-500/10 rounded-lg">
                      <AlertTriangle className="w-6 h-6 text-amber-500" />
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">Suspeitos</p>
                  <h3 className="text-3xl font-bold text-white mt-1">{stats.suspicious}</h3>
                </div>
                <div className="glass-panel p-6 border-l-4 border-l-green-500">
                  <div className="flex justify-between items-start mb-4">
                    <div className="p-2 bg-green-500/10 rounded-lg">
                      <ShieldCheck className="w-6 h-6 text-green-500" />
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm">Seguros</p>
                  <h3 className="text-3xl font-bold text-white mt-1">{stats.safe}</h3>
                </div>
              </div>

              {/* Recent Activity */}
              <div className="glass-panel p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-xl font-bold text-white flex items-center gap-2">
                    <History className="w-5 h-5 text-gold" />
                    Atividade Recente
                  </h3>
                  <button onClick={() => setView('history')} className="text-gold text-sm hover:underline">Ver tudo</button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-gray-500 text-sm border-b border-gold/10">
                        <th className="pb-4 font-medium">Tipo</th>
                        <th className="pb-4 font-medium">Conteúdo</th>
                        <th className="pb-4 font-medium">Score</th>
                        <th className="pb-4 font-medium">Status</th>
                        <th className="pb-4 font-medium">Data</th>
                      </tr>
                    </thead>
                    <tbody className="text-sm">
                      {scans.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="py-10 text-center text-gray-500 italic">
                            Nenhuma atividade recente detectada. Inicie uma varredura para começar.
                          </td>
                        </tr>
                      ) : (
                        scans.slice(0, 5).map((scan) => (
                          <tr key={scan.id} className="border-b border-gold/5 hover:bg-gold/5 transition-colors">
                            <td className="py-4">
                              <div className="flex items-center gap-2">
                                {scan.type === 'url' && <LinkIcon className="w-4 h-4 text-blue-400" />}
                                {scan.type === 'text' && <MessageSquare className="w-4 h-4 text-purple-400" />}
                                {scan.type === 'image' && <ImageIcon className="w-4 h-4 text-pink-400" />}
                                <span className="capitalize">{scan.type}</span>
                              </div>
                            </td>
                            <td className="py-4 max-w-xs truncate text-gray-300">{scan.content}</td>
                            <td className="py-4 font-mono font-bold">{scan.score}%</td>
                            <td className="py-4">
                              <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                                scan.status === 'safe' ? 'bg-green-500/10 text-green-500' :
                                scan.status === 'suspicious' ? 'bg-amber-500/10 text-amber-500' :
                                'bg-red-500/10 text-red-500'
                              }`}>
                                {scan.status === 'safe' ? 'Seguro' : scan.status === 'suspicious' ? 'Suspeito' : 'Golpe'}
                              </span>
                            </td>
                            <td className="py-4 text-gray-500">{new Date(scan.created_at).toLocaleDateString()}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {view === 'scan' && (
            <motion.div 
              key="scan"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="max-w-4xl mx-auto space-y-8"
            >
              <header>
                <h2 className="text-3xl font-bold text-white">Nova <span className="gold-text-gradient">Análise</span></h2>
                <p className="text-gray-400">Escolha o método de entrada para detecção de ameaças.</p>
              </header>

              <div className="grid grid-cols-3 gap-4">
                <button 
                  onClick={() => { setScanType('url'); setScanResult(null); setInput(''); }}
                  className={`p-6 glass-panel flex flex-col items-center gap-3 transition-all ${scanType === 'url' ? 'border-gold bg-gold/10' : 'hover:border-gold/50'}`}
                >
                  <LinkIcon className={`w-8 h-8 ${scanType === 'url' ? 'text-gold' : 'text-gray-500'}`} />
                  <span className="font-bold">URL</span>
                </button>
                <button 
                  onClick={() => { setScanType('text'); setScanResult(null); setInput(''); }}
                  className={`p-6 glass-panel flex flex-col items-center gap-3 transition-all ${scanType === 'text' ? 'border-gold bg-gold/10' : 'hover:border-gold/50'}`}
                >
                  <MessageSquare className={`w-8 h-8 ${scanType === 'text' ? 'text-gold' : 'text-gray-500'}`} />
                  <span className="font-bold">Texto</span>
                </button>
                <button 
                  onClick={() => { setScanType('image'); setScanResult(null); setInput(''); }}
                  className={`p-6 glass-panel flex flex-col items-center gap-3 transition-all ${scanType === 'image' ? 'border-gold bg-gold/10' : 'hover:border-gold/50'}`}
                >
                  <ImageIcon className={`w-8 h-8 ${scanType === 'image' ? 'text-gold' : 'text-gray-500'}`} />
                  <span className="font-bold">Imagem (OCR)</span>
                </button>
              </div>

              <div className="glass-panel p-8 space-y-6">
                {scanType === 'image' ? (
                  <div className="space-y-6">
                    <div className="flex flex-col items-center justify-center border-2 border-dashed border-gold/20 rounded-2xl p-12 hover:border-gold/50 transition-all cursor-pointer relative overflow-hidden">
                      {imageBase64 ? (
                        <img src={imageBase64} alt="Preview" className="absolute inset-0 w-full h-full object-cover opacity-30" />
                      ) : null}
                      <input 
                        type="file" 
                        accept="image/*" 
                        className="absolute inset-0 opacity-0 cursor-pointer" 
                        onChange={handleImageUpload}
                        disabled={isScanning}
                      />
                      <div className="w-16 h-16 bg-gold/10 rounded-full flex items-center justify-center mb-4 relative z-10">
                        <ImageIcon className="w-8 h-8 text-gold" />
                      </div>
                      <p className="font-bold text-white relative z-10">{imageBase64 ? 'Trocar Imagem' : 'Clique ou arraste o print aqui'}</p>
                      <p className="text-gray-400 text-sm mt-2 relative z-10">Formatos suportados: PNG, JPG, WEBP</p>
                    </div>
                    
                    {input && (
                      <div className="flex gap-4">
                        <button 
                          onClick={() => performScan(true)}
                          disabled={isScanning || isDeepScanning}
                          className="btn-gold flex-1 flex items-center justify-center gap-2"
                        >
                          {isDeepScanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Shield className="w-5 h-5" />}
                          {isDeepScanning ? 'Analisando Imagem com IA...' : 'Varredura Profunda (IA na Imagem)'}
                        </button>
                      </div>
                    )}
                  </div>
                ) : (
                  <>
                    <div className="space-y-2">
                      <label className="text-sm font-bold text-gold uppercase tracking-widest">
                        {scanType === 'url' ? 'Insira a URL suspeita' : 'Insira o texto da mensagem'}
                      </label>
                      <textarea 
                        className="input-field w-full h-32 resize-none"
                        placeholder={scanType === 'url' ? 'https://exemplo-banco.com/atualize-agora' : 'Olá, seu cartão foi bloqueado. Clique no link para verificar...'}
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                      />
                    </div>
                    <div className="flex gap-4">
                      <button 
                        onClick={() => performScan(false)}
                        disabled={isScanning || isDeepScanning || !input}
                        className="btn-gold flex-1 flex items-center justify-center gap-2"
                      >
                        {isScanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
                        {isScanning ? 'Analisando...' : 'Varredura Rápida'}
                      </button>
                      <button 
                        onClick={() => performScan(true)}
                        disabled={isScanning || isDeepScanning || !input}
                        className="bg-bank-black border border-gold text-gold font-bold py-3 px-6 rounded-xl transition-all hover:bg-gold/10 flex-1 flex items-center justify-center gap-2"
                      >
                        {isDeepScanning ? <Loader2 className="w-5 h-5 animate-spin" /> : <Shield className="w-5 h-5" />}
                        {isDeepScanning ? 'Consultando IA...' : 'Varredura Profunda (IA)'}
                      </button>
                    </div>
                  </>
                )}
              </div>

              {/* Results Display */}
              {scanResult && (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className={`glass-panel p-8 border-t-8 ${
                    scanResult.status === 'safe' ? 'border-t-green-500' :
                    scanResult.status === 'suspicious' ? 'border-t-amber-500' :
                    'border-t-red-500'
                  }`}
                >
                  <div className="flex items-start justify-between mb-8">
                    <div className="flex items-center gap-4">
                      <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${
                        scanResult.status === 'safe' ? 'bg-green-500/20 text-green-500' :
                        scanResult.status === 'suspicious' ? 'bg-amber-500/20 text-amber-500' :
                        'bg-red-500/20 text-red-500'
                      }`}>
                        {scanResult.status === 'safe' ? <ShieldCheck className="w-10 h-10" /> :
                         scanResult.status === 'suspicious' ? <AlertTriangle className="w-10 h-10" /> :
                         <ShieldAlert className="w-10 h-10" />}
                      </div>
                      <div>
                        <h3 className="text-2xl font-bold text-white">
                          {scanResult.status === 'safe' ? 'Resultado: Seguro' :
                           scanResult.status === 'suspicious' ? 'Resultado: Suspeito' :
                           'ALERTA: GOLPE DETECTADO!'}
                        </h3>
                        <p className="text-gray-400">Score de Risco: <span className="font-bold text-white">{scanResult.score}/100</span></p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase tracking-widest mb-1">Classificação</p>
                      <span className={`text-xl font-black uppercase ${
                        scanResult.status === 'safe' ? 'text-green-500' :
                        scanResult.status === 'suspicious' ? 'text-amber-500' :
                        'text-red-500'
                      }`}>
                        {scanResult.status === 'safe' ? 'Safe' : scanResult.status === 'suspicious' ? 'Warning' : 'Danger'}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h4 className="font-bold text-gold flex items-center gap-2">
                      <FileText className="w-4 h-4" />
                      Detalhes da Análise
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {scanResult.details.map((detail: string, i: number) => (
                        <div key={i} className="bg-bank-black/50 p-3 rounded-xl border border-gold/5 flex items-center gap-3">
                          <div className={`w-2 h-2 rounded-full ${
                            scanResult.status === 'safe' ? 'bg-green-500' :
                            scanResult.status === 'suspicious' ? 'bg-amber-500' :
                            'bg-red-500'
                          }`} />
                          <span className="text-sm text-gray-300">{detail}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {scanResult.status === 'danger' && (
                    <div className="mt-8 bg-red-500/10 border border-red-500/50 p-6 rounded-2xl flex items-center gap-6 animate-pulse">
                      <AlertCircle className="w-12 h-12 text-red-500 shrink-0" />
                      <div>
                        <p className="font-bold text-red-500 text-lg">RECOMENDAÇÃO CRÍTICA</p>
                        <p className="text-red-400/80 text-sm">Não clique em links, não forneça senhas ou dados pessoais. Este conteúdo apresenta padrões claros de phishing e engenharia social.</p>
                      </div>
                    </div>
                  )}
                </motion.div>
              )}
            </motion.div>
          )}

          {view === 'history' && (
            <motion.div 
              key="history"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-8"
            >
              <header>
                <h2 className="text-3xl font-bold text-white">Histórico <span className="gold-text-gradient">Completo</span></h2>
                <p className="text-gray-400">Todos os registros de varredura realizados.</p>
              </header>

              <div className="glass-panel overflow-hidden">
                <div className="p-6 border-b border-gold/10 flex items-center justify-between">
                  <div className="flex gap-2">
                    <button className="px-4 py-2 bg-gold text-bank-black text-xs font-bold rounded-lg">Todos</button>
                    <button className="px-4 py-2 bg-bank-black border border-gold/20 text-gray-400 text-xs font-bold rounded-lg hover:text-gold transition-colors">Golpes</button>
                    <button className="px-4 py-2 bg-bank-black border border-gold/20 text-gray-400 text-xs font-bold rounded-lg hover:text-gold transition-colors">Seguros</button>
                  </div>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    <input type="text" placeholder="Buscar no histórico..." className="bg-bank-black border border-gold/20 rounded-lg pl-10 pr-4 py-2 text-xs focus:outline-none focus:border-gold" />
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-gray-500 text-sm border-b border-gold/10">
                        <th className="p-6 font-medium">Tipo</th>
                        <th className="p-6 font-medium">Conteúdo Analisado</th>
                        <th className="p-6 font-medium">Risco</th>
                        <th className="p-6 font-medium">Status</th>
                        <th className="p-6 font-medium">Data e Hora</th>
                      </tr>
                    </thead>
                    <tbody className="text-sm">
                      {scans.map((scan) => (
                        <tr key={scan.id} className="border-b border-gold/5 hover:bg-gold/5 transition-colors group">
                          <td className="p-6">
                            <div className="flex items-center gap-2">
                              {scan.type === 'url' && <LinkIcon className="w-4 h-4 text-blue-400" />}
                              {scan.type === 'text' && <MessageSquare className="w-4 h-4 text-purple-400" />}
                              {scan.type === 'image' && <ImageIcon className="w-4 h-4 text-pink-400" />}
                              <span className="capitalize text-gray-400">{scan.type}</span>
                            </div>
                          </td>
                          <td className="p-6">
                            <p className="max-w-md truncate text-gray-200 font-medium">{scan.content}</p>
                          </td>
                          <td className="p-6">
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                                <div 
                                  className={`h-full ${
                                    scan.score > 70 ? 'bg-red-500' :
                                    scan.score > 30 ? 'bg-amber-500' :
                                    'bg-green-500'
                                  }`}
                                  style={{ width: `${scan.score}%` }}
                                />
                              </div>
                              <span className="font-mono text-xs">{scan.score}%</span>
                            </div>
                          </td>
                          <td className="p-6">
                            <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                              scan.status === 'safe' ? 'bg-green-500/10 text-green-500' :
                              scan.status === 'suspicious' ? 'bg-amber-500/10 text-amber-500' :
                              'bg-red-500/10 text-red-500'
                            }`}>
                              {scan.status === 'safe' ? 'Seguro' : scan.status === 'suspicious' ? 'Suspeito' : 'Golpe'}
                            </span>
                          </td>
                          <td className="p-6 text-gray-500">
                            {new Date(scan.created_at).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </motion.div>
          )}

          {view === 'official_sites' && (
            <motion.div 
              key="official_sites"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="space-y-8"
            >
              <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-3xl font-bold text-white">Diretório <span className="gold-text-gradient">Oficial</span></h2>
                  <p className="text-gray-400">Lista verificada de domínios e links legítimos de instituições financeiras.</p>
                </div>
                <div className="flex flex-col md:flex-row gap-4 w-full md:w-auto">
                  <div className="relative w-full md:w-64">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gold/50" />
                    <input 
                      type="text" 
                      placeholder="Buscar..." 
                      className="input-field w-full pl-12"
                      value={officialSearch}
                      onChange={(e) => setOfficialSearch(e.target.value)}
                    />
                  </div>
                  <button 
                    onClick={() => setIsAddingSite(true)}
                    className="btn-gold flex items-center justify-center gap-2"
                  >
                    <ShieldCheck className="w-5 h-5" />
                    Cadastrar Novo
                  </button>
                </div>
              </header>

              <AnimatePresence>
                {isAddingSite && (
                  <motion.div 
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="glass-panel p-6 overflow-hidden"
                  >
                    <h3 className="text-lg font-bold text-white mb-4">Cadastrar Instituição Oficial</h3>
                    <form onSubmit={handleAddSite} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      <input 
                        type="text" 
                        placeholder="Nome (ex: Banco X)" 
                        className="input-field"
                        value={newSite.name}
                        onChange={(e) => setNewSite({...newSite, name: e.target.value})}
                        required
                      />
                      <input 
                        type="text" 
                        placeholder="Domínio (ex: bancox.com.br)" 
                        className="input-field"
                        value={newSite.domain}
                        onChange={(e) => setNewSite({...newSite, domain: e.target.value})}
                        onBlur={fetchOfficialLinks}
                        required
                      />
                      <div className="relative">
                        <input 
                          type="text" 
                          placeholder="Sublinks (separados por vírgula)" 
                          className="input-field w-full pr-24"
                          value={newSite.sublinks}
                          onChange={(e) => setNewSite({...newSite, sublinks: e.target.value})}
                        />
                        <button 
                          type="button"
                          onClick={fetchOfficialLinks}
                          disabled={isFetchingLinks || !newSite.domain}
                          className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-1 bg-gold/20 text-gold text-[10px] rounded-lg hover:bg-gold/30 disabled:opacity-50 transition-all font-bold"
                        >
                          {isFetchingLinks ? <Loader2 className="w-3 h-3 animate-spin" /> : 'Buscar Links'}
                        </button>
                      </div>
                      <div className="flex gap-2">
                        <input 
                          type="color" 
                          className="w-12 h-12 bg-transparent border-none cursor-pointer"
                          value={newSite.color}
                          onChange={(e) => setNewSite({...newSite, color: e.target.value})}
                        />
                        <button type="submit" className="btn-gold flex-1">Salvar</button>
                        <button 
                          type="button" 
                          onClick={() => setIsAddingSite(false)}
                          className="px-4 py-2 bg-red-500/10 text-red-500 rounded-xl hover:bg-red-500/20 transition-all"
                        >
                          Cancelar
                        </button>
                      </div>
                    </form>
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {[...OFFICIAL_BANK_SITES, ...customSites].filter(bank => 
                  bank.name.toLowerCase().includes(officialSearch.toLowerCase()) || 
                  bank.domain.toLowerCase().includes(officialSearch.toLowerCase())
                ).map((bank, index) => (
                  <motion.div 
                    key={index}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className="glass-panel p-6 border-l-4 hover:bg-gold/5 transition-all group"
                    style={{ borderLeftColor: bank.color }}
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <h3 className="text-xl font-bold text-white group-hover:text-gold transition-colors">{bank.name}</h3>
                        <div className="flex flex-col gap-1 mt-1">
                          <div className="flex items-center gap-2">
                            <ShieldCheck className="w-4 h-4 text-green-500" />
                            <span className="text-sm font-mono text-gray-400">{bank.domain}</span>
                          </div>
                          {(bank as any).domain_age && (
                            <div className="flex items-center gap-2">
                              <TrendingUp className="w-3 h-3 text-gold/50" />
                              <span className="text-[10px] text-gold/70 font-bold uppercase tracking-widest">Tempo Online: {(bank as any).domain_age}</span>
                            </div>
                          )}
                        </div>
                      </div>
                      <a 
                        href={`https://${bank.domain}`} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="p-2 bg-gold/10 rounded-lg text-gold hover:bg-gold hover:text-bank-black transition-all"
                      >
                        <LinkIcon className="w-5 h-5" />
                      </a>
                    </div>

                    <div className="space-y-2">
                      <p className="text-xs text-gray-500 uppercase tracking-widest font-bold">Links Verificados</p>
                      <div className="flex flex-wrap gap-2">
                        {Array.isArray(bank.sublinks) ? bank.sublinks.map((sub, i) => (
                          <div key={i} className="px-3 py-1 bg-bank-black/50 border border-gold/10 rounded-md text-[10px] text-gray-300 font-mono">
                            {bank.domain}{sub}
                          </div>
                        )) : (
                          <span className="text-[10px] text-gray-500 italic">Nenhum link adicional listado</span>
                        )}
                      </div>
                    </div>

                    <div className="mt-6 pt-4 border-t border-gold/5 flex items-center justify-between">
                      <span className="text-[10px] text-green-500/70 font-bold uppercase tracking-tighter flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        Autenticidade Garantida
                      </span>
                      <div className="flex items-center gap-3">
                        {customSites.some(cs => cs.id === (bank as any).id) && (
                          <button 
                            onClick={() => handleDeleteSite((bank as any).id)}
                            className="text-xs text-red-500 hover:underline flex items-center gap-1"
                            title="Remover"
                          >
                            <Trash2 className="w-3 h-3" />
                            Remover
                          </button>
                        )}
                        <button 
                          onClick={() => {
                            setInput(`https://${bank.domain}`);
                            setScanType('url');
                            setView('scan');
                          }}
                          className="text-xs text-gold hover:underline"
                        >
                          Testar este site
                        </button>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>

              <div className="bg-blue-500/10 border border-blue-500/30 p-6 rounded-2xl flex items-start gap-4">
                <AlertCircle className="w-6 h-6 text-blue-400 shrink-0 mt-1" />
                <div>
                  <p className="font-bold text-blue-400">Dica de Segurança</p>
                  <p className="text-blue-300/70 text-sm mt-1">
                    Sempre verifique se o cadeado está presente na barra de endereços e se o domínio termina exatamente como listado acima. 
                    Golpistas costumam usar domínios parecidos como <code className="bg-bank-black px-1 rounded">itau-seguranca.com</code> ou <code className="bg-bank-black px-1 rounded">nubank.net</code>.
                  </p>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
