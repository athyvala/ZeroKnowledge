// content-script.js - AI-powered privacy protection for elderly assistance
(async function() {
    'use strict';
    
    console.log('🤖 Session Sharer AI content script loading...');
    
    // AI-powered content filtering class - AI-FIRST approach
    class SessionAI {
        constructor() {
            this.model = null;
            this.isLoading = false;
            this.isEnabled = true;
            this.maskedElements = new Set();
            
            // Hugging Face API configuration
            this.huggingFaceApiKey = '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';
            this.huggingFaceModels = {
                ner: 'dslim/bert-base-NER',
                pii: 'microsoft/DialoGPT-medium'
            };
            
            // Minimal regex patterns as absolute fallback only
            this.criticalPatterns = {
                ssn: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
                creditCard: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
            };
        
            // URLs that should be blocked for elderly assistance
            this.blockedPaths = [
                'settings', 'profile', 'account', 'billing', 'payment', 'payments',
                'personal', 'edit', 'modify', 'delete', 'remove', 'cancel',
                'security', 'password', 'preferences', 'config', 'configuration',
                'bank', 'financial', 'money', 'transfer', 'withdraw', 'deposit',
                'credit-card', 'creditcard', 'debit', 'autopay', 'auto-pay',
                'medical-records', 'health-records', 'prescription', 'medication',
                'diagnosis', 'treatment', 'doctor', 'physician', 'specialist',
                'claims', 'benefits', 'coverage', 'premium', 'deductible',
                'beneficiary', 'emergency-contact', 'next-of-kin'
            ];

            // Performance tracking
            this.performanceMetrics = {
                totalScans: 0,
                totalMasked: 0,
                totalBlocked: 0,
                aiCalls: 0,
                aiErrors: 0,
                regexFallbacks: 0
            };

            // AI-focused caching
            this.aiCache = new Map();
            this.maxCacheSize = 200; // Larger cache for AI results
        }
        
        async initialize() {
            if (this.isLoading) return;
            this.isLoading = true;

            try {
                console.log('🤖 Initializing AI-first protection system...');
                
                // Test API connection - this is critical now
                const testResult = await this.testHuggingFaceConnection();
                if (testResult) {
                    this.model = 'huggingface';
                    this.modelType = 'ai-primary';
                    console.log('✅ Hugging Face AI is primary detection method');
                } else {
                    this.model = 'limited-fallback';
                    this.modelType = 'regex-fallback';
                    console.warn('⚠️ AI unavailable - using limited regex fallback only');
                }
                
                this.isLoading = false;
                return true;
                
            } catch (error) {
                console.error('❌ AI initialization failed:', error);
                this.model = 'limited-fallback';
                this.modelType = 'regex-fallback';
                this.isLoading = false;
                return false;
            }
        }

        async testHuggingFaceConnection() {
            try {
                console.log('🧪 Testing AI connection...');
                const response = await this.callHuggingFaceAPI('test john.doe@email.com', this.huggingFaceModels.ner);
                console.log('🧪 AI test response:', response);
                return response && !response.error;
            } catch (error) {
                console.warn('🧪 AI connection test failed:', error);
                return false;
            }
        }

        async callHuggingFaceAPI(text, model) {
            try {
                this.performanceMetrics.aiCalls++;
                
                const response = await fetch(`https://api-inference.huggingface.co/models/${model}`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.huggingFaceApiKey}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ 
                        inputs: text,
                        options: { 
                            wait_for_model: true,
                            use_cache: false // Get fresh results
                        }
                    })
                });

                if (!response.ok) {
                    throw new Error(`API call failed: ${response.status} ${response.statusText}`);
                }

                const result = await response.json();
                console.log(`🤖 AI analyzed: "${text.substring(0, 50)}..." → ${result.length || 0} entities found`);
                return result;
                
            } catch (error) {
                this.performanceMetrics.aiErrors++;
                console.error('🚫 AI API error:', error);
                throw error;
            }
        }

        async analyzeSensitivity(text) {
            // Skip very short text
            if (text.length < 3) {
                return { isSensitive: false, confidence: 0 };
            }

            // Check cache first
            const cacheKey = this.hashString(text);
            if (this.aiCache.has(cacheKey)) {
                return this.aiCache.get(cacheKey);
            }

            let result = { isSensitive: false, confidence: 0 };

            // PRIMARY: Use AI for everything if available
            if (this.model === 'huggingface') {
                try {
                    result = await this.analyzeWithAI(text);
                } catch (error) {
                    console.warn('🚫 AI analysis failed, using fallback:', error);
                    result = this.analyzeCriticalPatternsOnly(text);
                }
            } else {
                // FALLBACK: Only check absolutely critical patterns
                result = this.analyzeCriticalPatternsOnly(text);
            }

            // Cache the result
            if (this.aiCache.size >= this.maxCacheSize) {
                const firstKey = this.aiCache.keys().next().value;
                this.aiCache.delete(firstKey);
            }
            this.aiCache.set(cacheKey, result);

            return result;
        }

        async analyzeWithAI(text) {
            try {
                // Use NER model to detect entities
                const entities = await this.callHuggingFaceAPI(text, this.huggingFaceModels.ner);
                
                if (entities && Array.isArray(entities)) {
                    // Look for ANY potentially sensitive entities with lower threshold
                    const sensitiveEntities = entities.filter(entity => {
                        const entityType = entity.entity_group || entity.entity || '';
                        const score = entity.score || 0;
                        
                        // Detect persons, organizations, locations, and miscellaneous entities
                        const isSensitiveType = [
                            'B-PER', 'I-PER', 'PERSON', 'PER',           // People
                            'B-ORG', 'I-ORG', 'ORG',                    // Organizations  
                            'B-LOC', 'I-LOC', 'LOC', 'LOCATION',        // Locations
                            'B-MISC', 'I-MISC', 'MISC',                 // Miscellaneous (often IDs, emails, etc.)
                            'EMAIL', 'PHONE', 'DATE', 'MONEY'           // Specific types
                        ].includes(entityType.toUpperCase());
                        
                        return isSensitiveType && score > 0.5; // Lower threshold for AI
                    });

                    if (sensitiveEntities.length > 0) {
                        const maxConfidence = Math.max(...sensitiveEntities.map(e => e.score));
                        console.log(`🎯 AI detected ${sensitiveEntities.length} sensitive entities:`, sensitiveEntities.map(e => `${e.entity_group}(${e.score.toFixed(2)})`));
                        
                        return {
                            isSensitive: true,
                            confidence: maxConfidence,
                            method: 'huggingface-ai',
                            entities: sensitiveEntities,
                            details: entities
                        };
                    }
                }

                // Even if NER doesn't find entities, check for patterns that look sensitive
                const contextualAnalysis = this.analyzeContextualSensitivity(text);
                if (contextualAnalysis.isSensitive) {
                    return contextualAnalysis;
                }

                return { isSensitive: false, confidence: 0, method: 'ai-analysis' };
                
            } catch (error) {
                console.error('🚫 AI analysis error:', error);
                throw error;
            }
        }

        analyzeContextualSensitivity(text) {
            const lowerText = text.toLowerCase();
            const originalText = text;
            
            // Enhanced ID detection patterns - covers all major ID types
            const idPatterns = [
                // Email patterns (even if AI missed them)
                {
                    pattern: /@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
                    type: 'email',
                    confidence: 0.95
                },
                
                // Phone patterns (multiple formats)
                {
                    pattern: /\b\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b/,
                    type: 'phone',
                    confidence: 0.9
                },
                {
                    pattern: /\b(\+?1[-.\s]?)?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b/,
                    type: 'phone',
                    confidence: 0.9
                },
                
                // Government ID patterns
                {
                    pattern: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/, // SSN
                    type: 'ssn',
                    confidence: 0.95
                },
                
                // Passport patterns (various countries)
                {
                    pattern: /\b[A-Z]{1,2}\d{6,9}\b/, // US passport format
                    type: 'passport',
                    confidence: 0.85
                },
                {
                    pattern: /\b\d{9}\b/, // 9-digit passport numbers
                    type: 'passport',
                    confidence: 0.75
                },
                
                // Driver's License patterns (various states)
                {
                    pattern: /\b[A-Z]\d{7,8}\b/, // Format: A1234567
                    type: 'drivers_license',
                    confidence: 0.8
                },
                {
                    pattern: /\b\d{8,9}\b/, // 8-9 digit DL numbers
                    type: 'drivers_license',
                    confidence: 0.7
                },
                {
                    pattern: /\b[A-Z]{1,2}\d{6,8}[A-Z]?\b/, // Mixed format DL
                    type: 'drivers_license',
                    confidence: 0.8
                },
                
                // State ID patterns
                {
                    pattern: /\b[A-Z]{2,3}\d{6,12}\b/, // State ID format
                    type: 'state_id',
                    confidence: 0.8
                },
                
                // Generic government ID patterns
                {
                    pattern: /\b[A-Z0-9]{8,15}\b/, // General alphanumeric IDs
                    type: 'government_id',
                    confidence: 0.6
                },
                
                // Credit card patterns
                {
                    pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/,
                    type: 'credit_card',
                    confidence: 0.9
                },
                {
                    pattern: /\b\d{15,16}\b/, // 15-16 digit credit cards
                    type: 'credit_card',
                    confidence: 0.8
                },
                
                // Money patterns
                {
                    pattern: /\$[\d,]+\.?\d*/,
                    type: 'money',
                    confidence: 0.7
                },
                
                // Date patterns (potential DOB)
                {
                    pattern: /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/,
                    type: 'date',
                    confidence: 0.6
                },
                {
                    pattern: /\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](\d{2}|\d{4})\b/,
                    type: 'date',
                    confidence: 0.8
                },
                
                // Address patterns
                {
                    pattern: /\b\d+\s+[A-Za-z\s]+(street|st|avenue|ave|road|rd|drive|dr|lane|ln|blvd|boulevard|way|court|ct|place|pl)\b/i,
                    type: 'address',
                    confidence: 0.8
                },
                
                // Insurance/Medical ID patterns
                {
                    pattern: /\b[A-Z]{2,4}\d{6,12}\b/, // Insurance member IDs
                    type: 'insurance_id',
                    confidence: 0.8
                },
                
                // Account numbers
                {
                    pattern: /\b\d{6,20}\b/, // Long numeric sequences (account numbers)
                    type: 'account_number',
                    confidence: 0.5
                }
            ];

            // Test each pattern
            for (const idPattern of idPatterns) {
                if (idPattern.pattern.test(originalText)) {
                    console.log(`🆔 ID pattern detected: ${idPattern.type} in "${text}"`);
                    return {
                        isSensitive: true,
                        confidence: idPattern.confidence,
                        method: 'id-pattern-detection',
                        idType: idPattern.type,
                        pattern: idPattern.pattern.toString()
                    };
                }
            }

            // Enhanced keyword detection for ALL types of IDs
            const comprehensiveIdKeywords = [
                // Government IDs
                'passport', 'passport number', 'passport #',
                'driver license', 'drivers license', 'dl number', 'license number',
                'state id', 'state identification', 'id card', 'identification card',
                'social security', 'ssn', 'social security number',
                'tax id', 'taxpayer id', 'ein', 'federal id',
                'voter id', 'voter registration',
                
                // International IDs
                'national id', 'national identification', 'citizen id',
                'resident card', 'green card', 'visa number',
                'immigration number', 'alien number',
                
                // Healthcare IDs
                'patient id', 'patient number', 'medical record', 'mrn',
                'member id', 'subscriber id', 'policy number', 'group number',
                'insurance card', 'health plan', 'medicaid', 'medicare',
                'provider id', 'npi', 'dea number',
                
                // Financial IDs
                'account number', 'routing number', 'aba number',
                'credit card', 'debit card', 'card number',
                'bank account', 'checking account', 'savings account',
                'loan number', 'mortgage number',
                
                // Employment/Professional IDs
                'employee id', 'badge number', 'staff id',
                'professional license', 'certification number',
                'union number', 'membership number',
                
                // Personal Information
                'date of birth', 'dob', 'birth date',
                'phone number', 'telephone', 'mobile number',
                'email address', 'email',
                'home address', 'mailing address', 'billing address',
                'emergency contact', 'next of kin',
                
                // Student IDs
                'student id', 'student number', 'school id',
                'university id', 'college id'
            ];

            // Check for ID keywords with context
            for (const keyword of comprehensiveIdKeywords) {
                if (lowerText.includes(keyword)) {
                    console.log(`🔑 ID keyword found: "${keyword}" in "${text}"`);
                    return {
                        isSensitive: true,
                        confidence: 0.9,
                        method: 'id-keyword-detection',
                        keyword: keyword,
                        idCategory: this.categorizeIdKeyword(keyword)
                    };
                }
            }

            // Check for contextual clues that suggest ID information
            const idContextClues = [
                'number:', 'id:', '#:', 'no:', 'num:',
                'expires:', 'issued:', 'valid until:',
                'cardholder:', 'holder:', 'name on card:',
                'member since:', 'issued to:', 'belongs to:'
            ];

            for (const clue of idContextClues) {
                if (lowerText.includes(clue)) {
                    // If we find a context clue, check if there's an ID-like pattern nearby
                    const textAfterClue = originalText.substring(lowerText.indexOf(clue));
                    if (/[A-Z0-9]{4,}/.test(textAfterClue.substring(0, 50))) {
                        console.log(`🔍 ID context clue found: "${clue}" with potential ID in "${text}"`);
                        return {
                            isSensitive: true,
                            confidence: 0.8,
                            method: 'id-context-detection',
                            contextClue: clue
                        };
                    }
                }
            }

            return { isSensitive: false, confidence: 0 };
        }

        // Helper function to categorize ID types
        categorizeIdKeyword(keyword) {
            const categories = {
                government: ['passport', 'driver', 'license', 'state id', 'social security', 'ssn', 'tax id', 'voter'],
                healthcare: ['patient', 'medical', 'member', 'subscriber', 'policy', 'insurance', 'medicaid', 'medicare', 'npi'],
                financial: ['account', 'routing', 'credit', 'debit', 'bank', 'loan', 'mortgage'],
                personal: ['phone', 'email', 'address', 'birth', 'dob', 'emergency'],
                professional: ['employee', 'badge', 'professional', 'certification', 'union'],
                education: ['student', 'school', 'university', 'college']
            };

            for (const [category, keywords] of Object.entries(categories)) {
                if (keywords.some(k => keyword.includes(k))) {
                    return category;
                }
            }
            return 'general';
        }

        analyzeCriticalPatternsOnly(text) {
            this.performanceMetrics.regexFallbacks++;
            console.warn('⚠️ Using regex fallback for:', text.substring(0, 30) + '...');
            
            for (const [type, pattern] of Object.entries(this.criticalPatterns)) {
                if (pattern.test(text)) {
                    return {
                        isSensitive: true,
                        confidence: 0.95,
                        method: 'critical-regex-fallback',
                        detectedType: type
                    };
                }
            }
            
            return { isSensitive: false, confidence: 0 };
        }

        hashString(str) {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return hash.toString();
        }

        async scanAndMaskPageBatched() {
            if (!this.isEnabled) return 0;
            
            console.log('🔍 AI-powered page scan starting...');
            const startTime = performance.now();
            
            let maskedCount = 0;
            const textNodes = this.getAllTextNodes();
            
            console.log(`📄 Found ${textNodes.length} text nodes to analyze`);
            
            // PHASE 1: Regular text analysis
            const batchSize = 5;
            for (let i = 0; i < textNodes.length; i += batchSize) {
                const batch = textNodes.slice(i, i + batchSize);
                console.log(`🔄 Processing batch ${Math.floor(i/batchSize) + 1}/${Math.ceil(textNodes.length/batchSize)}`);
                
                const promises = batch.map(async (textNode) => {
                    const text = textNode.textContent.trim();
                    if (text.length < 3) return null;
                    
                    const analysis = await this.analyzeSensitivity(text);
                    
                    if (analysis.isSensitive && analysis.confidence > 0.4) {
                        return { textNode, analysis };
                    }
                    return null;
                });
                
                const results = await Promise.all(promises);
                
                results.forEach(result => {
                    if (result) {
                        this.maskTextNode(result.textNode, result.analysis);
                        maskedCount++;
                        console.log(`🛡️ Masked: "${result.textNode.textContent.substring(0, 30)}..." (${result.analysis.method})`);
                        
                        // PHASE 2: Look for related values near field labels
                        if (this.isFieldLabel(result.analysis)) {
                            const relatedValues = this.findRelatedValues(result.textNode);
                            relatedValues.forEach(valueNode => {
                                if (!this.maskedElements.has(valueNode.parentElement)) {
                                    this.maskTextNode(valueNode, {
                                        isSensitive: true,
                                        confidence: 0.8,
                                        method: 'related-to-field-label',
                                        relatedTo: result.analysis
                                    });
                                    maskedCount++;
                                    console.log(`🔗 Masked related value: "${valueNode.textContent.substring(0, 30)}..."`);
                                }
                            });
                        }
                    }
                });
                
                await new Promise(resolve => setTimeout(resolve, 200));
            }
            
            // PHASE 3: Contextual scanning for missed values
            maskedCount += await this.scanForMissedValues();
            
            const duration = performance.now() - startTime;
            this.performanceMetrics.totalScans++;
            this.performanceMetrics.totalMasked += maskedCount;
            
            console.log(`🎯 AI scan complete: ${maskedCount} items masked in ${duration.toFixed(2)}ms`);
            console.log(`📊 AI calls: ${this.performanceMetrics.aiCalls}, Errors: ${this.performanceMetrics.aiErrors}, Regex fallbacks: ${this.performanceMetrics.regexFallbacks}`);
            
            return maskedCount;
        }

        // Check if the analysis result indicates a field label
        isFieldLabel(analysis) {
            if (analysis.method === 'id-keyword-detection' || analysis.method === 'keyword-context') {
                return true;
            }
            
            if (analysis.keyword) {
                const fieldIndicators = ['number', 'id', 'address', 'phone', 'email', 'passport', 'license', 'card'];
                return fieldIndicators.some(indicator => analysis.keyword.includes(indicator));
            }
            
            return false;
        }

        // Find related values near a field label
        findRelatedValues(labelNode) {
            const relatedNodes = [];
            const labelElement = labelNode.parentElement;
            
            // Strategy 1: Look in the same parent container
            const siblings = Array.from(labelElement.parentNode.children);
            const labelIndex = siblings.indexOf(labelElement);
            
            // Check next few siblings
            for (let i = labelIndex + 1; i < Math.min(labelIndex + 4, siblings.length); i++) {
                const sibling = siblings[i];
                const textNodes = this.getTextNodesFromElement(sibling);
                textNodes.forEach(textNode => {
                    if (this.looksLikeValue(textNode.textContent)) {
                        relatedNodes.push(textNode);
                    }
                });
            }
            
            // Strategy 2: Look in table cells (common layout)
            const cell = labelElement.closest('td, th');
            if (cell) {
                const nextCell = cell.nextElementSibling;
                if (nextCell) {
                    const textNodes = this.getTextNodesFromElement(nextCell);
                    textNodes.forEach(textNode => {
                        if (this.looksLikeValue(textNode.textContent)) {
                            relatedNodes.push(textNode);
                        }
                    });
                }
            }
            
            // Strategy 3: Look for input fields nearby
            const nearbyInputs = this.findNearbyInputs(labelElement);
            nearbyInputs.forEach(input => {
                if (input.value && this.looksLikeValue(input.value)) {
                    // Create a text node for the input value
                    const valueNode = document.createTextNode(input.value);
                    relatedNodes.push(valueNode);
                    // We'll need to handle input masking differently
                    this.maskInputField(input);
                }
            });
            
            // Strategy 4: Look in the same line/row
            const sameLineElements = this.findElementsInSameLine(labelElement);
            sameLineElements.forEach(element => {
                const textNodes = this.getTextNodesFromElement(element);
                textNodes.forEach(textNode => {
                    if (textNode !== labelNode && this.looksLikeValue(textNode.textContent)) {
                        relatedNodes.push(textNode);
                    }
                });
            });
            
            return relatedNodes;
        }

        // Check if text looks like a value rather than a label
        looksLikeValue(text) {
            const trimmedText = text.trim();
            
            // Skip very short text or obvious labels
            if (trimmedText.length < 3 || trimmedText.endsWith(':') || trimmedText.endsWith('*')) {
                return false;
            }
            
            // Look for patterns that suggest this is a value
            const valuePatterns = [
                /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/, // SSN
                /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, // Credit card
                /\b\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b/, // Phone
                /@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, // Email
                /\b[A-Z]{1,2}\d{6,9}\b/, // Passport-like
                /\b[A-Z0-9]{6,15}\b/, // ID-like
                /\b\d+\s+[A-Za-z\s]+(street|st|avenue|ave|road|rd|drive|dr|lane|ln)\b/i, // Address
                /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/, // Date
                /\$[\d,]+\.?\d*/ // Money
            ];
            
            return valuePatterns.some(pattern => pattern.test(trimmedText));
        }

        // Get text nodes from an element
        getTextNodesFromElement(element) {
            const walker = document.createTreeWalker(
                element,
                NodeFilter.SHOW_TEXT,
                {
                    acceptNode: (node) => {
                        const parentTag = node.parentElement?.tagName;
                        if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(parentTag)) {
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

        // Find input fields near a label
        findNearbyInputs(labelElement) {
            const inputs = [];
            
            // Look for inputs with matching labels
            const labelFor = labelElement.getAttribute('for');
            if (labelFor) {
                const associatedInput = document.getElementById(labelFor);
                if (associatedInput) inputs.push(associatedInput);
            }
            
            // Look for inputs in the same container
            const container = labelElement.closest('div, form, fieldset, table, tr');
            if (container) {
                const nearbyInputs = container.querySelectorAll('input, select, textarea');
                nearbyInputs.forEach(input => {
                    if (!inputs.includes(input)) {
                        inputs.push(input);
                    }
                });
            }
            
            return inputs;
        }

        // Find elements that appear to be in the same line
        findElementsInSameLine(referenceElement) {
            const elements = [];
            const rect = referenceElement.getBoundingClientRect();
            
            // Find elements with similar vertical position
            const allElements = document.querySelectorAll('*');
            allElements.forEach(element => {
                if (element === referenceElement) return;
                
                const elemRect = element.getBoundingClientRect();
                const verticalOverlap = Math.abs(elemRect.top - rect.top) < 10 || 
                                       Math.abs(elemRect.bottom - rect.bottom) < 10;
                
                if (verticalOverlap && elemRect.left > rect.right && elemRect.left < rect.right + 300) {
                    elements.push(element);
                }
            });
            
            return elements;
        }

        // Mask input fields
        maskInputField(input) {
            const originalValue = input.value;
            
            if (this.looksLikeValue(originalValue)) {
                // Store original value
                input.dataset.originalValue = originalValue;
                
                // Apply appropriate masking based on input type
                let maskedValue = originalValue;
                
                if (input.type === 'email' || /@/.test(originalValue)) {
                    maskedValue = '●●●●●@●●●●.●●●';
                } else if (input.type === 'tel' || /\d{3}.*\d{3}.*\d{4}/.test(originalValue)) {
                    maskedValue = '(●●●) ●●●-●●●●';
                } else if (/\d{3}[-.]?\d{2}[-.]?\d{4}/.test(originalValue)) {
                    maskedValue = '●●●-●●-●●●●';
                } else {
                    maskedValue = '●'.repeat(Math.min(originalValue.length, 12));
                }
                
                input.value = maskedValue;
                input.style.cssText += `
                    background: linear-gradient(135deg, #fff3cd, #ffeaa7) !important;
                    border: 2px solid #28a745 !important;
                    font-weight: bold !important;
                `;
                
                input.title = '🤖 AI Protected: Input field value masked';
                
                // Prevent editing of masked fields
                input.addEventListener('focus', (e) => {
                    e.target.blur();
                    this.showElderlyFriendlyNotification(
                        'Protected Field',
                        'This field contains sensitive information and cannot be edited.'
                    );
                });
            }
        }

        // Scan for values that might have been missed in the first pass
        async scanForMissedValues() {
            console.log('🔍 Scanning for missed values...');
            let additionalMasked = 0;
            
            // Look for common value patterns that weren't caught
            const allTextNodes = this.getAllTextNodes();
            
            for (const textNode of allTextNodes) {
                if (this.maskedElements.has(textNode.parentElement)) {
                    continue; // Already masked
                }
                
                const text = textNode.textContent.trim();
                
                // Check for standalone values that look sensitive
                if (this.looksLikeStandaloneValue(text)) {
                    const analysis = {
                        isSensitive: true,
                        confidence: 0.7,
                        method: 'missed-value-detection',
                        pattern: 'standalone-sensitive-value'
                    };
                    
                    this.maskTextNode(textNode, analysis);
                    additionalMasked++;
                    console.log(`🎯 Caught missed value: "${text.substring(0, 30)}..."`);
                }
            }
            
            return additionalMasked;
        }

        // Check if text looks like a standalone sensitive value
        looksLikeStandaloneValue(text) {
            const trimmedText = text.trim();
            
            // Skip if too short or looks like a label
            if (trimmedText.length < 6 || 
                trimmedText.includes(':') || 
                trimmedText.toLowerCase().includes('number') ||
                trimmedText.toLowerCase().includes('id')) {
                return false;
            }
            
            // High-confidence patterns for standalone values
            const standalonePatterns = [
                /^\d{3}[-.]?\d{2}[-.]?\d{4}$/, // SSN format
                /^\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}$/, // Credit card format
                /^\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})$/, // Phone format
                /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/, // Email format
                /^[A-Z]{1,2}\d{6,9}$/, // Passport format
                /^[A-Z]\d{7,8}$/, // Driver's license format
                /^\d{8,16}$/, // Long number (account, etc.)
                /^[A-Z0-9]{8,15}$/ // Alphanumeric ID
            ];
            
            return standalonePatterns.some(pattern => pattern.test(trimmedText));
        }

        getAllTextNodes() {
            const walker = document.createTreeWalker(
                document.body,
                NodeFilter.SHOW_TEXT,
                {
                    acceptNode: (node) => {
                        // Skip script and style elements
                        const parentTag = node.parentElement?.tagName;
                        if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(parentTag)) {
                            return NodeFilter.FILTER_REJECT;
                        }
                        
                        const text = node.textContent.trim();
                        return text.length > 0 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
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
            
            if (this.maskedElements.has(parent)) return;
            this.maskedElements.add(parent);

            // AI-powered smart masking with ID-specific handling
            let maskedText = originalText;
            
            if (analysis.entities && analysis.entities.length > 0) {
                // Mask based on AI-detected entities
                analysis.entities.forEach(entity => {
                    const entityText = entity.word || '';
                    if (entityText && originalText.includes(entityText)) {
                        const replacement = '●'.repeat(Math.min(entityText.length, 12));
                        maskedText = maskedText.replace(new RegExp(entityText.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), replacement);
                    }
                });
            }
            
            // Enhanced ID-specific masking patterns
            if (maskedText === originalText) {
                const idMaskingPatterns = [
                    // Email masking
                    { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: '●●●●●@●●●●.●●●' },
                    
                    // Phone number masking
                    { pattern: /\b\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b/g, replacement: '(●●●) ●●●-●●●●' },
                    
                    // SSN masking
                    { pattern: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g, replacement: '●●●-●●-●●●●' },
                    
                    // Credit card masking
                    { pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, replacement: '●●●● ●●●● ●●●● ●●●●' },
                    
                    // Passport/ID masking (alphanumeric)
                    { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, replacement: (match) => '●'.repeat(match.length) },
                    
                    // Driver's license masking
                    { pattern: /\b[A-Z]\d{7,8}\b/g, replacement: (match) => '●'.repeat(match.length) },
                    
                    // Generic long numbers (account numbers, etc.)
                    { pattern: /\b\d{8,}\b/g, replacement: (match) => '●'.repeat(Math.min(match.length, 12)) },
                    
                    // Generic alphanumeric IDs
                    { pattern: /\b[A-Z0-9]{6,15}\b/g, replacement: (match) => '●'.repeat(Math.min(match.length, 10)) }
                ];

                idMaskingPatterns.forEach(maskPattern => {
                    if (typeof maskPattern.replacement === 'function') {
                        maskedText = maskedText.replace(maskPattern.pattern, maskPattern.replacement);
                    } else {
                        maskedText = maskedText.replace(maskPattern.pattern, maskPattern.replacement);
                    }
                });
            }
            
            // If still no specific masking applied, do intelligent partial masking
            if (maskedText === originalText) {
                if (originalText.length < 50) {
                    // For short text, mask most but leave some structure
                    if (originalText.length <= 8) {
                        maskedText = '●'.repeat(originalText.length);
                    } else {
                        // Show first and last character, mask middle
                        maskedText = originalText[0] + '●'.repeat(originalText.length - 2) + originalText[originalText.length - 1];
                    }
                } else {
                    // For longer text, mask key parts
                    maskedText = originalText.replace(/[A-Z0-9]{3,}/g, match => '●'.repeat(Math.min(match.length, 8)));
                }
            }

            textNode.textContent = maskedText;
            
            // Enhanced styling based on ID type
            let borderColor = '#28a745'; // Default green
            let bgGradient = 'linear-gradient(135deg, #fff3cd, #ffeaa7)';
            
            if (analysis.idType) {
                switch (analysis.idCategory || analysis.idType) {
                    case 'government':
                    case 'passport':
                    case 'drivers_license':
                    case 'ssn':
                        borderColor = '#dc3545'; // Red for government IDs
                        bgGradient = 'linear-gradient(135deg, #f8d7da, #f5c6cb)';
                        break;
                    case 'financial':
                    case 'credit_card':
                    case 'account_number':
                        borderColor = '#fd7e14'; // Orange for financial
                        bgGradient = 'linear-gradient(135deg, #fff3cd, #ffeaa7)';
                        break;
                    case 'healthcare':
                    case 'insurance_id':
                        borderColor = '#20c997'; // Teal for healthcare
                        bgGradient = 'linear-gradient(135deg, #d1ecf1, #bee5eb)';
                        break;
                }
            }
            
            parent.style.cssText += `
                background: ${bgGradient} !important;
                border: 2px solid ${borderColor} !important;
                border-radius: 6px !important;
                padding: 4px 8px !important;
                position: relative !important;
                font-weight: bold !important;
                box-shadow: 0 2px 4px rgba(0,0,0,0.15) !important;
                margin: 2px !important;
            `;
            
            // Enhanced tooltip with ID type information
            const idTypeText = analysis.idType ? ` (${analysis.idType.replace('_', ' ').toUpperCase()})` : '';
            parent.title = `🤖 AI Protected ID${idTypeText}: ${analysis.method} (${Math.round(analysis.confidence * 100)}% confidence)`;
        }

        shouldBlockNavigation(url) {
            const path = url.toLowerCase();
            const blocked = this.blockedPaths.some(blockedPath => 
                path.includes(blockedPath)
            );
            
            if (blocked) {
                console.log(`🚫 AI blocking navigation to: ${url}`);
                this.performanceMetrics.totalBlocked++;
            }
            
            return blocked;
        }

        interceptNavigation() {
            document.addEventListener('click', (e) => {
                const link = e.target.closest('a');
                if (link && link.href) {
                    if (this.shouldBlockNavigation(link.href)) {
                        e.preventDefault();
                        e.stopPropagation();
                        this.showElderlyFriendlyNotification(
                            'AI Protection Active', 
                            `This area contains personal information and has been blocked by AI for your protection.`
                        );
                        return false;
                    }
                }
            }, true);

            document.addEventListener('submit', (e) => {
                const form = e.target;
                const action = form.action || window.location.href;
                
                if (this.shouldBlockNavigation(action)) {
                    e.preventDefault();
                    this.showElderlyFriendlyNotification(
                        'AI Protection Active',
                        'This form leads to a restricted area and has been blocked by AI.'
                    );
                    return false;
                }
            }, true);
        }

        showElderlyFriendlyNotification(title, message) {
            const existing = document.querySelector('.session-ai-notification');
            if (existing) existing.remove();

            const notification = document.createElement('div');
            notification.className = 'session-ai-notification';
            notification.style.cssText = `
                position: fixed !important;
                top: 50% !important;
                left: 50% !important;
                transform: translate(-50%, -50%) !important;
                background: linear-gradient(135deg, #28a745, #20c997) !important;
                color: white !important;
                padding: 25px 30px !important;
                border-radius: 12px !important;
                z-index: 999999 !important;
                font-family: -apple-system, BlinkMacSystemFont, sans-serif !important;
                font-size: 16px !important;
                font-weight: 500 !important;
                box-shadow: 0 8px 32px rgba(0,0,0,0.3) !important;
                max-width: 400px !important;
                text-align: center !important;
                border: 3px solid #fff !important;
            `;
            
            notification.innerHTML = `
                <div style="font-size: 24px; margin-bottom: 10px;">🤖</div>
                <div style="font-size: 18px; font-weight: bold; margin-bottom: 8px;">${title}</div>
                <div style="font-size: 14px; line-height: 1.4; margin-bottom: 15px;">${message}</div>
                <div style="font-size: 12px; opacity: 0.9;">AI-Powered Privacy Protection</div>
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 5000);
        }

        setEnabled(enabled) {
            this.isEnabled = enabled;
            console.log(`🤖 AI protection ${enabled ? 'enabled' : 'disabled'}`);
            
            if (!enabled) {
                this.maskedElements.forEach(element => {
                    element.style.backgroundColor = '';
                    element.style.border = '';
                    element.title = '';
                });
                this.maskedElements.clear();
            }
        }

        getStatus() {
            return {
                enabled: this.isEnabled,
                modelLoaded: !!this.model,
                loading: this.isLoading,
                maskedCount: this.maskedElements.size,
                metrics: this.performanceMetrics,
                aiPrimary: this.model === 'huggingface'
            };
        }
    }
    
    // Initialize the AI system
    let ai = null;
    let isInitializing = false;
    
    // Set up message listener immediately
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        console.log('📨 Received message:', request.action);
        
        if (request.action === 'toggleAI') {
            if (ai) {
                ai.setEnabled(request.enabled);
                if (request.enabled) {
                    ai.scanAndMaskPageBatched();
                }
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: 'AI not initialized yet' });
            }
            return true;
            
        } else if (request.action === 'testAI') {
            if (ai) {
                ai.scanAndMaskPageBatched().then(count => {
                    sendResponse({ maskedCount: count, status: ai.getStatus() });
                }).catch(error => {
                    sendResponse({ maskedCount: 0, status: { error: error.message } });
                });
                return true;
            } else {
                sendResponse({ maskedCount: 0, status: { error: 'AI not initialized yet' } });
            }
            return true;
            
        } else if (request.action === 'getAIStatus') {
            if (ai) {
                sendResponse(ai.getStatus());
            } else if (isInitializing) {
                sendResponse({ 
                    enabled: true, 
                    modelLoaded: false, 
                    loading: true, 
                    maskedCount: 0 
                });
            } else {
                sendResponse({ 
                    enabled: false, 
                    modelLoaded: false, 
                    loading: false, 
                    maskedCount: 0,
                    error: 'AI not started'
                });
            }
            return true;
        }
    });

    // Initialize AI
    async function initializeAI() {
        try {
            isInitializing = true;
            console.log('🚀 Initializing AI-first system...');
            
            ai = new SessionAI();
            const modelLoaded = await ai.initialize();
            
            // Set up navigation interception
            ai.interceptNavigation();
            
            // Initial page scan
            if (document.readyState === 'complete') {
                setTimeout(() => ai.scanAndMaskPageBatched(), 1000);
            } else {
                window.addEventListener('load', () => {
                    setTimeout(() => ai.scanAndMaskPageBatched(), 1000);
                });
            }

            // Monitor for dynamic content changes
            const observer = new MutationObserver((mutations) => {
                let shouldRescan = false;
                
                mutations.forEach(mutation => {
                    if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                        for (const node of mutation.addedNodes) {
                            if (node.nodeType === Node.TEXT_NODE || 
                                (node.nodeType === Node.ELEMENT_NODE && node.innerText)) {
                                shouldRescan = true;
                                break;
                            }
                        }
                    }
                });

                if (shouldRescan) {
                    clearTimeout(window.aiRescanTimeout);
                    window.aiRescanTimeout = setTimeout(() => {
                        console.log('🔄 Rescanning due to page changes...');
                        ai.scanAndMaskPageBatched();
                    }, 2000); // Longer delay for AI processing
                }
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true,
                characterData: true
            });

            window.sessionAI = ai;
            isInitializing = false;
            console.log('🛡️ AI-first protection system active');
            
        } catch (error) {
            console.error('❌ Failed to initialize AI:', error);
            isInitializing = false;
        }
    }

    // Check if AI should run
    async function shouldRunAI() {
        try {
            const result = await chrome.storage.local.get(['aiEnabled']);
            return result.aiEnabled !== false;
        } catch (error) {
            return true;
        }
    }

    // Main initialization
    async function init() {
        if (await shouldRunAI()) {
            await initializeAI();
        }
    }

    // Start the process
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Add visual indicator
    function addAIIndicator() {
        if (document.getElementById('session-ai-indicator')) return;
        
        const indicator = document.createElement('div');
        indicator.id = 'session-ai-indicator';
        indicator.style.cssText = `
            position: fixed !important;
            bottom: 20px !important;
            left: 20px !important;
            background: linear-gradient(135deg, #007bff, #0056b3) !important;
            color: white !important;
            padding: 10px 15px !important;
            border-radius: 25px !important;
            font-size: 14px !important;
            font-family: -apple-system, BlinkMacSystemFont, sans-serif !important;
            z-index: 999998 !important;
            opacity: 0.9 !important;
            pointer-events: none !important;
            font-weight: 600 !important;
            border: 2px solid #fff !important;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
        `;
        indicator.textContent = '🤖 AI-Powered Protection';
        
        if (document.body) {
            document.body.appendChild(indicator);
            
            setTimeout(() => {
                if (indicator.parentNode) {
                    indicator.style.opacity = '0.6';
                }
            }, 3000);
        }
    }

    window.addEventListener('load', () => {
        setTimeout(addAIIndicator, 1000);
    });

})();