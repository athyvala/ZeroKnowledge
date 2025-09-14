// ai-filter.js - AI-powered content filtering with Hugging Face API
class SessionAI {
    constructor() {
      this.model = null;
      this.isLoading = false;
      this.isEnabled = true;
      this.maskedElements = new Set();
      
      // Hugging Face API configuration - hardcoded for simplicity
      this.huggingFaceApiKey = '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';
      this.huggingFaceModels = {
        ner: 'dslim/bert-base-NER',
        pii: 'microsoft/DialoGPT-medium'
      };
      
      // Simple patterns for immediate detection
      this.sensitivePatterns = {
        ssn: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
        creditCard: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
        phone: /\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
        accountNumber: /\b(?:account|acct|acc)[\s#:]*[A-Z]*\d{6,}\b/gi,
        money: /\$[\d,]+\.\d{2}/g,
        email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        
        // Healthcare specific
        memberID: /\b(?:member|patient|policy)[\s#:]*[A-Z0-9]{6,15}\b/gi,
        medicalRecord: /\b(?:mrn|medical record)[\s#:]*[A-Z0-9]{6,12}\b/gi,
        insuranceGroup: /\b(?:group|grp)[\s#:]*[A-Z0-9]{3,10}\b/gi,
        npiNumber: /\b(?:npi)[\s#:]*\d{10}\b/gi,
        claimNumber: /\b(?:claim)[\s#:]*[A-Z0-9]{8,15}\b/gi,
        
        // Date patterns that might be DOB
        dateOfBirth: /\b(?:dob|date of birth)[\s:]*\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4}\b/gi,
        
        // ID card numbers
        idCard: /\b(?:id|card)[\s#:]*[A-Z0-9]{6,12}\b/gi
      };
  
      // URLs that should be blocked
      this.blockedPaths = [
        'settings', 'profile', 'account', 'billing', 'payment',
        'personal', 'edit', 'modify', 'delete', 'security', 
        'password', 'preferences', 'config'
      ];

      // Add caching for performance
      this.analysisCache = new Map();
      this.maxCacheSize = 100;
      
      // Batch processing
      this.processingQueue = [];
      this.isProcessingBatch = false;

      // Add to constructor
      this.performanceMetrics = {
        totalScans: 0,
        totalMasked: 0,
        averageTime: 0,
        cacheHits: 0,
        apiCalls: 0,
        apiErrors: 0
      };
    }
  
    async initialize() {
      if (this.isLoading) return;
      this.isLoading = true;

      try {
        console.log('🤖 Initializing AI protection system...');
        
        // API key is hardcoded, so test connection directly
        const testResult = await this.testHuggingFaceConnection();
        if (testResult) {
          this.model = 'huggingface';
          this.modelType = 'huggingface-ner';
          console.log('✅ Hugging Face API connected successfully');
        } else {
          // Fallback to enhanced pattern matching
          this.model = 'enhanced-patterns';
          this.modelType = 'pattern-enhanced';
          console.log('⚠️ Hugging Face API failed, using enhanced patterns');
        }
        
        this.isLoading = false;
        return true;
        
      } catch (error) {
        console.warn('⚠️ AI model failed to load, using regex fallback:', error);
        this.model = 'patterns-only';
        this.modelType = 'regex';
        this.isLoading = false;
        return false;
      }
    }

    async testHuggingFaceConnection() {
      try {
        const response = await this.callHuggingFaceAPI('test connection', this.huggingFaceModels.ner);
        return response && !response.error;
      } catch (error) {
        console.warn('Hugging Face API test failed:', error);
        return false;
      }
    }

    async callHuggingFaceAPI(text, model) {
      try {
        this.performanceMetrics.apiCalls++;
        
        const response = await fetch(`https://api-inference.huggingface.co/models/${model}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.huggingFaceApiKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ 
            inputs: text,
            options: { wait_for_model: true }
          })
        });

        if (!response.ok) {
          throw new Error(`API call failed: ${response.status}`);
        }

        const result = await response.json();
        return result;
        
      } catch (error) {
        this.performanceMetrics.apiErrors++;
        console.error('Hugging Face API error:', error);
        throw error;
      }
    }

    async analyzeSensitivity(text) {
      // Quick pattern check first (instant)
      const regexResult = this.checkPatterns(text);
      if (regexResult.isSensitive) {
        return regexResult;
      }

      // Use Hugging Face API for deeper analysis if available
      if (this.model === 'huggingface' && text.length > 10 && text.length < 300) {
        try {
          const entities = await this.callHuggingFaceAPI(text, this.huggingFaceModels.ner);
          
          if (entities && Array.isArray(entities)) {
            const sensitiveEntities = entities.filter(entity => 
              ['B-PER', 'I-PER', 'B-ORG', 'I-ORG', 'B-MISC', 'I-MISC', 'PERSON', 'ORG'].includes(entity.entity_group || entity.entity) &&
              entity.score > 0.7
            );

            if (sensitiveEntities.length > 0) {
              return {
                isSensitive: true,
                confidence: Math.max(...sensitiveEntities.map(e => e.score)),
                method: 'huggingface-ner',
                entities: sensitiveEntities,
                details: entities
              };
            }
          }
        } catch (error) {
          console.warn('Hugging Face analysis failed, falling back to patterns:', error);
          return regexResult;
        }
      }

      // Enhanced keyword detection
      const keywordResult = this.checkSensitiveKeywords(text);
      if (keywordResult.isSensitive) {
        return keywordResult;
      }

      return regexResult;
    }

    // Enhanced keyword detection
    checkSensitiveKeywords(text) {
      const healthcareKeywords = [
        'patient id', 'member id', 'policy number', 'group number', 'subscriber id',
        'medical record', 'mrn', 'insurance card', 'copay', 'deductible',
        'diagnosis', 'prescription', 'medication', 'treatment', 'claim number',
        'provider id', 'npi', 'date of birth', 'dob', 'ssn', 'social security'
      ];
      
      const financialKeywords = [
        'account number', 'routing number', 'credit card', 'debit card',
        'bank account', 'checking', 'savings', 'balance', 'statement'
      ];
      
      const personalKeywords = [
        'home address', 'phone number', 'email address', 'driver license',
        'passport', 'emergency contact', 'next of kin'
      ];
      
      const allKeywords = [...healthcareKeywords, ...financialKeywords, ...personalKeywords];
      const lowerText = text.toLowerCase();
      
      const foundKeywords = allKeywords.filter(keyword => 
        lowerText.includes(keyword)
      );
      
      if (foundKeywords.length > 0) {
        return {
          isSensitive: true,
          confidence: 0.8,
          method: 'keyword-detection',
          foundKeywords: foundKeywords
        };
      }
      
      return { isSensitive: false, confidence: 0 };
    }
  
    checkPatterns(text) {
      const detectedTypes = [];
      let maxConfidence = 0;
  
      for (const [type, pattern] of Object.entries(this.sensitivePatterns)) {
        if (pattern.test(text)) {
          detectedTypes.push(type);
          maxConfidence = Math.max(maxConfidence, 0.9);
        }
      }
  
      return {
        isSensitive: detectedTypes.length > 0,
        confidence: maxConfidence,
        method: 'regex-patterns',
        detectedTypes: detectedTypes
      };
    }

    containsSensitiveKeywords(text) {
      const sensitiveWords = [
        'password', 'ssn', 'social security', 'credit card', 'account number',
        'routing number', 'pin', 'security code', 'cvv', 'personal information'
      ];
      
      const lowerText = text.toLowerCase();
      return sensitiveWords.some(word => lowerText.includes(word));
    }

    // Add caching to avoid re-analyzing the same text
    async analyzeSensitivityCached(text) {
      const cacheKey = this.hashString(text);
      
      if (this.analysisCache.has(cacheKey)) {
        this.performanceMetrics.cacheHits++;
        return this.analysisCache.get(cacheKey);
      }
      
      const result = await this.analyzeSensitivity(text);
      
      // Manage cache size
      if (this.analysisCache.size >= this.maxCacheSize) {
        const firstKey = this.analysisCache.keys().next().value;
        this.analysisCache.delete(firstKey);
      }
      
      this.analysisCache.set(cacheKey, result);
      return result;
    }

    // Simple hash function for caching
    hashString(str) {
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
      }
      return hash.toString();
    }

    // Batch processing for better performance
    async scanAndMaskPageBatched() {
      const startTime = performance.now();
      if (!this.isEnabled || this.isProcessingBatch) return;
      
      this.isProcessingBatch = true;
      console.log('🔍 Scanning page for sensitive content (batched)...');
      
      let maskedCount = 0;
      const textNodes = this.getAllTextNodes();
      
      // Process in batches of 10
      const batchSize = 10;
      for (let i = 0; i < textNodes.length; i += batchSize) {
        const batch = textNodes.slice(i, i + batchSize);
        
        const promises = batch.map(async (textNode) => {
          const text = textNode.textContent.trim();
          if (text.length < 3) return null;
          
          const analysis = await this.analyzeSensitivityCached(text);
          
          if (analysis.isSensitive && analysis.confidence > 0.6) {
            return { textNode, analysis };
          }
          return null;
        });
        
        const results = await Promise.all(promises);
        
        results.forEach(result => {
          if (result) {
            this.maskTextNode(result.textNode, result.analysis);
            maskedCount++;
          }
        });
        
        // Small delay between batches to avoid blocking the UI
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      
      this.isProcessingBatch = false;
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      this.performanceMetrics.totalScans++;
      this.performanceMetrics.totalMasked += maskedCount;
      this.performanceMetrics.averageTime = 
        (this.performanceMetrics.averageTime + duration) / 2;
      
      console.log(`⚡ Scan completed in ${duration.toFixed(2)}ms`);
      return maskedCount;
    }

    getAllTextNodes() {
      const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        {
          acceptNode: (node) => {
            // Skip script and style elements
            if (node.parentElement.tagName === 'SCRIPT' || 
                node.parentElement.tagName === 'STYLE') {
              return NodeFilter.FILTER_REJECT;
            }
            return node.textContent.trim().length > 0 ? 
              NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
          }
        }
      );

      const textNodes = [];
      let node;
      while (node = walker.nextNode()) {
        textNodes.push(node);
      }
      
      return textNodes;
    }
  
    maskTextNode(textNode, analysis) {
      const originalText = textNode.textContent;
      const parent = textNode.parentElement;
      
      // Don't mask the same element twice
      if (this.maskedElements.has(parent)) return;
      this.maskedElements.add(parent);

      // Create masked version
      let maskedText = originalText;
      
      // Apply pattern-specific masking
      for (const [type, pattern] of Object.entries(this.sensitivePatterns)) {
        if (analysis.detectedTypes?.includes(type)) {
          maskedText = maskedText.replace(pattern, (match) => {
            return '●'.repeat(Math.min(match.length, 12));
          });
        }
      }

      // If no specific patterns, mask the whole thing if it's short
      if (maskedText === originalText && originalText.length < 50) {
        maskedText = '●'.repeat(Math.min(originalText.length, 20));
      }

      // Apply masking
      textNode.textContent = maskedText;
      
      // Style the parent element
      parent.style.cssText += `
        background-color: #fff3cd !important;
        border: 1px solid #ffeaa7 !important;
        border-radius: 3px !important;
        padding: 2px 4px !important;
        position: relative !important;
      `;
      
      parent.title = `🛡️ Sensitive information masked by AI (${analysis.method}, ${Math.round(analysis.confidence * 100)}% confidence)`;
      
      // Add hover to reveal (for debugging)
      parent.addEventListener('mouseenter', () => {
        if (parent.dataset.revealed !== 'true') {
          parent.style.backgroundColor = '#f8f9fa';
        }
      });

      parent.addEventListener('mouseleave', () => {
        if (parent.dataset.revealed !== 'true') {
          parent.style.backgroundColor = '#fff3cd';
        }
      });
    }
  
    shouldBlockNavigation(url) {
      const path = url.toLowerCase();
      const blocked = this.blockedPaths.some(blockedPath => 
        path.includes(blockedPath)
      );
      
      if (blocked) {
        console.log(`🚫 Blocking navigation to: ${url}`);
      }
      
      return blocked;
    }
  
    interceptNavigation() {
      // Block dangerous clicks
      document.addEventListener('click', (e) => {
        const link = e.target.closest('a');
        if (link && link.href) {
          if (this.shouldBlockNavigation(link.href)) {
            e.preventDefault();
            e.stopPropagation();
            this.showBlockedNotification(`Navigation blocked: ${link.textContent || 'Link'}`);
            return false;
          }
        }
      }, true);

      // Block form submissions to sensitive endpoints
      document.addEventListener('submit', (e) => {
        const form = e.target;
        const action = form.action || window.location.href;
        
        if (this.shouldBlockNavigation(action)) {
          e.preventDefault();
          this.showBlockedNotification('Form submission blocked: Sensitive endpoint');
          return false;
        }
      }, true);
    }
  
    showBlockedNotification(message) {
      // Remove any existing notifications
      const existing = document.querySelector('.session-ai-notification');
      if (existing) existing.remove();

      const notification = document.createElement('div');
      notification.className = 'session-ai-notification';
      notification.style.cssText = `
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: #dc3545 !important;
        color: white !important;
        padding: 15px 20px !important;
        border-radius: 8px !important;
        z-index: 999999 !important;
        font-family: -apple-system, BlinkMacSystemFont, sans-serif !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3) !important;
        max-width: 300px !important;
        word-wrap: break-word !important;
      `;
      
      notification.innerHTML = `
        <div>🛡️ ${message}</div>
        <div style="font-size: 12px; margin-top: 5px; opacity: 0.9;">
          Session Sharer AI Protection
        </div>
      `;
      
      document.body.appendChild(notification);
      
      // Auto-remove after 4 seconds
      setTimeout(() => {
        if (notification.parentNode) {
          notification.remove();
        }
      }, 4000);
    }
  
    // Toggle AI protection on/off
    setEnabled(enabled) {
      this.isEnabled = enabled;
      console.log(`🤖 AI protection ${enabled ? 'enabled' : 'disabled'}`);
      
      if (!enabled) {
        // Remove all masking
        this.maskedElements.forEach(element => {
          element.style.backgroundColor = '';
          element.style.border = '';
          element.title = '';
        });
        this.maskedElements.clear();
      }
    }
  
    // Get current status
    getStatus() {
      return {
        enabled: this.isEnabled,
        modelLoaded: !!this.model,
        loading: this.isLoading,
        maskedCount: this.maskedElements.size
      };
    }

    // Method to get performance stats
    getPerformanceStats() {
      return {
        ...this.performanceMetrics,
        cacheSize: this.analysisCache.size
      };
    }
  }
  
// Make sure SessionAI is immediately available
console.log('🎯 Making SessionAI available globally...');
window.SessionAI = SessionAI;

// Also create an instance for debugging
const sessionAI = new SessionAI();
window.sessionAI = sessionAI;

console.log('✅ SessionAI class exported to window:', typeof window.SessionAI);