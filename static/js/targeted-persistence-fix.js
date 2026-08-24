/**
 * TARGETED FIX FOR FORM PERSISTENCE ISSUES
 * 
 * This is a more surgical fix that only addresses frontend persistence
 * without interfering with database connectivity.
 * 
 * Fixes:
 * 1. SSO field mapping persistence in edit form UI
 * 2. Dynamic dropdown configuration persistence 
 * 3. Frontend-backend synchronization issues
 */

// Enhanced SSO Mapping Population (Frontend Only)
function enhanceSsoMappingPersistence() {
    console.log('🔧 Enhancing SSO mapping persistence...');
    
    // Store the original function if it exists
    if (typeof populateSsoFieldMappings !== 'undefined') {
        window.originalPopulateSsoFieldMappings = populateSsoFieldMappings;
    }
    
    // Enhanced version that better handles existing data
    window.populateSsoFieldMappings = function() {
        console.log('=== ENHANCED SSO FIELD MAPPINGS POPULATION ===');
        
        const formFields = Array.from(formFieldsContainer.children).map(fieldItem => ({
            name: fieldItem.querySelector('.field-name').value || '',
            label: fieldItem.querySelector('.field-label').value || 'Unnamed Field',
            type: fieldItem.querySelector('.field-type').value || 'text'
        })).filter(field => field.name.trim() !== '');

        const ssoFieldMappings = document.getElementById('ssoFieldMappings');
        
        if (!ssoFieldMappings || formFields.length === 0) {
            console.log('SSO mappings container not found or no fields available');
            return;
        }

        // Enhanced data loading with multiple fallback methods
        let existingMappings = {};
        try {
            // Method 1: Django json_script
            const ssoFieldsElement = document.getElementById('sso-prepopulate-fields-data');
            if (ssoFieldsElement && ssoFieldsElement.textContent.trim()) {
                existingMappings = JSON.parse(ssoFieldsElement.textContent);
                console.log('✅ Loaded from json_script:', existingMappings);
            } else {
                // Method 2: Template variable fallback
                const templateData = '{{ sso_prepopulate_fields_json|escapejs }}';
                if (templateData && templateData !== '{}' && templateData !== 'None') {
                    existingMappings = JSON.parse(templateData.replace(/\\u0022/g, '"'));
                    console.log('✅ Loaded from template:', existingMappings);
                }
            }
        } catch (e) {
            console.log('Using empty mappings due to parse error:', e);
            existingMappings = {};
        }
        
        // Clear and repopulate
        ssoFieldMappings.innerHTML = '';
        
        formFields.forEach((field, index) => {
            const existingMapping = existingMappings[field.name] || '';
            
            const mappingDiv = document.createElement('div');
            mappingDiv.className = 'row g-3 mb-3 sso-field-mapping';
            mappingDiv.innerHTML = `
                <div class="col-md-4">
                    <label class="form-label">${field.label}</label>
                    <input type="text" class="form-control" value="${field.name}" readonly>
                    <small class="text-muted">Field: ${field.name} (${field.type})</small>
                </div>
                <div class="col-md-4">
                    <label class="form-label">SSO Attribute</label>
                    <select class="form-select sso-attribute" name="sso_mapping_${field.name}">
                        <option value="">No mapping</option>
                        <option value="email" ${existingMapping === 'email' ? 'selected' : ''}>Email</option>
                        <option value="username" ${existingMapping === 'username' ? 'selected' : ''}>Username</option>
                        <option value="first_name" ${existingMapping === 'first_name' ? 'selected' : ''}>First Name</option>
                        <option value="last_name" ${existingMapping === 'last_name' ? 'selected' : ''}>Last Name</option>
                        <option value="full_name" ${existingMapping === 'full_name' ? 'selected' : ''}>Full Name</option>
                        <option value="department" ${existingMapping === 'department' ? 'selected' : ''}>Department</option>
                        <option value="title" ${existingMapping === 'title' ? 'selected' : ''}>Job Title</option>
                        <option value="phone" ${existingMapping === 'phone' ? 'selected' : ''}>Phone Number</option>
                    </select>
                </div>
                <div class="col-md-4 d-flex align-items-end">
                    ${existingMapping ? '<span class="badge bg-success">Mapped</span>' : '<span class="badge bg-secondary">Not mapped</span>'}
                </div>
            `;
            
            ssoFieldMappings.appendChild(mappingDiv);
        });
        
        console.log('✅ SSO field mappings populated with persistence');
    };
}

// Enhanced Dynamic Options Configuration Loading (Frontend Only)
function enhanceDynamicOptionsPersistence() {
    console.log('🔧 Enhancing dynamic options persistence...');
    
    // Store original function
    if (typeof getDynamicOptionsConfiguration !== 'undefined') {
        window.originalGetDynamicOptionsConfiguration = getDynamicOptionsConfiguration;
    }
    
    // Enhanced version
    window.getDynamicOptionsConfiguration = function() {
        console.log('=== ENHANCED DYNAMIC OPTIONS LOADING ===');
        
        let savedConfig = {};
        try {
            const dbConfig = '{{ form.dynamic_options_config|escapejs }}';
            if (dbConfig && dbConfig !== 'None' && dbConfig !== '' && dbConfig !== '{}') {
                savedConfig = JSON.parse(dbConfig);
                console.log('✅ Loaded dynamic config:', savedConfig);
                
                // Apply configurations to form fields
                setTimeout(() => {
                    Object.keys(savedConfig).forEach(fieldName => {
                        restoreDynamicFieldConfiguration(fieldName, savedConfig[fieldName]);
                    });
                }, 1000);
            }
        } catch (e) {
            console.log('Error parsing dynamic config:', e);
        }
        
        return savedConfig;
    };
}

// Helper function to restore dynamic field configuration
function restoreDynamicFieldConfiguration(fieldName, config) {
    console.log(`🔄 Restoring config for field: ${fieldName}`, config);
    
    // Find the field element
    const fieldItems = Array.from(formFieldsContainer.children);
    const fieldItem = fieldItems.find(item => {
        const nameInput = item.querySelector('.field-name');
        return nameInput && nameInput.value === fieldName;
    });
    
    if (!fieldItem) {
        console.log(`Field ${fieldName} not found`);
        return;
    }
    
    // Set to dynamic options if not already
    const dynamicRadio = fieldItem.querySelector('input[value="dynamic"]');
    if (dynamicRadio && !dynamicRadio.checked) {
        dynamicRadio.checked = true;
        dynamicRadio.dispatchEvent(new Event('change'));
        
        // Wait for UI to update, then set values
        setTimeout(() => {
            setDynamicFieldValues(fieldItem, config);
        }, 800);
    } else {
        setDynamicFieldValues(fieldItem, config);
    }
}

// Helper function to set dynamic field values
function setDynamicFieldValues(fieldItem, config) {
    // Set connection
    const connectionSelect = fieldItem.querySelector('.dynamic-connection');
    if (connectionSelect && config.connection_id) {
        connectionSelect.value = config.connection_id;
        connectionSelect.dispatchEvent(new Event('change'));
    }
    
    // Set query mode
    if (config.query_mode) {
        const modeRadio = fieldItem.querySelector(`input[value="${config.query_mode}"]`);
        if (modeRadio) {
            modeRadio.checked = true;
            modeRadio.dispatchEvent(new Event('change'));
        }
    }
    
    // For guided mode, set table and columns
    if (config.query_mode === 'guided') {
        setTimeout(() => {
            const tableSelect = fieldItem.querySelector('.dynamic-table');
            if (tableSelect && config.table) {
                tableSelect.value = config.table;
                tableSelect.dispatchEvent(new Event('change'));
                
                setTimeout(() => {
                    const valueColumnSelect = fieldItem.querySelector('.dynamic-value-column');
                    const labelColumnSelect = fieldItem.querySelector('.dynamic-label-column');
                    
                    if (valueColumnSelect && config.value_column) {
                        valueColumnSelect.value = config.value_column;
                    }
                    if (labelColumnSelect && config.label_column) {
                        labelColumnSelect.value = config.label_column;
                    }
                    
                    // Restore where conditions
                    if (config.where_conditions && config.where_conditions.length > 0) {
                        setTimeout(() => {
                            restoreWhereConditionsForField(fieldItem, config.where_conditions);
                        }, 500);
                    }
                }, 500);
            }
        }, 500);
    }
}

// Helper function to restore where conditions
function restoreWhereConditionsForField(fieldItem, whereConditions) {
    console.log('🔄 Restoring where conditions:', whereConditions);
    
    const whereContainer = fieldItem.querySelector('.where-conditions');
    if (!whereContainer) return;
    
    whereConditions.forEach((condition, index) => {
        // Use existing addWhereCondition function if available
        if (typeof addWhereCondition === 'function') {
            addWhereCondition(fieldItem);
            
            setTimeout(() => {
                const conditionRows = whereContainer.querySelectorAll('.where-condition-row');
                const conditionRow = conditionRows[conditionRows.length - 1];
                
                if (conditionRow) {
                    const columnSelect = conditionRow.querySelector('.where-column');
                    const operatorSelect = conditionRow.querySelector('.where-operator');
                    const valueInput = conditionRow.querySelector('.where-value');
                    const logicSelect = conditionRow.querySelector('.where-logic');
                    
                    if (columnSelect) columnSelect.value = condition.column || '';
                    if (operatorSelect) operatorSelect.value = condition.operator || '=';
                    if (valueInput) valueInput.value = condition.value || '';
                    if (logicSelect) logicSelect.value = condition.logic || 'AND';
                }
            }, 200 * (index + 1));
        }
    });
}

// Enhanced SSO Disabled Fields Persistence
function enhanceSsoDisabledFieldsPersistence() {
    console.log('🔧 Enhancing SSO disabled fields persistence...');
    
    if (typeof populateSsoDisabledFields !== 'undefined') {
        window.originalPopulateSsoDisabledFields = populateSsoDisabledFields;
    }
    
    window.populateSsoDisabledFields = function() {
        console.log('=== ENHANCED SSO DISABLED FIELDS POPULATION ===');
        
        const container = document.getElementById('ssoDisabledFields');
        if (!container) return;
        
        container.innerHTML = '';
        
        // Load existing disabled fields
        let existingDisabledFields = [];
        try {
            const templateData = '{{ sso_disabled_fields_json|safe }}';
            if (templateData && templateData !== '[]' && templateData !== 'null') {
                existingDisabledFields = JSON.parse(templateData);
            }
        } catch (e) {
            console.log('Error loading disabled fields:', e);
        }
        
        if (Array.isArray(existingDisabledFields) && existingDisabledFields.length > 0) {
            existingDisabledFields.forEach(fieldName => {
                const fieldDiv = document.createElement('div');
                fieldDiv.className = 'row g-2 mb-2 align-items-end';
                fieldDiv.innerHTML = `
                    <div class="col-md-10">
                        <label class="form-label">Form Field Name</label>
                        <input type="text" class="form-control sso-disabled-field" value="${fieldName}">
                    </div>
                    <div class="col-md-2">
                        <button type="button" class="btn btn-sm btn-outline-danger" onclick="removeSsoDisabledField(this)">
                            <i class="ki-duotone ki-trash fs-6"></i>
                        </button>
                    </div>
                `;
                container.appendChild(fieldDiv);
            });
        }
    };
}

// Initialize all enhancements
function initializePersistenceEnhancements() {
    console.log('🚀 Initializing targeted persistence enhancements...');
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(() => {
                enhanceSsoMappingPersistence();
                enhanceDynamicOptionsPersistence();
                enhanceSsoDisabledFieldsPersistence();
                
                // Initialize configurations after form fields are loaded
                setTimeout(() => {
                    if (typeof getDynamicOptionsConfiguration === 'function') {
                        getDynamicOptionsConfiguration();
                    }
                    
                    // Trigger SSO mapping population if enabled
                    const enableSsoCheckbox = document.getElementById('enableSsoPrepopulate');
                    if (enableSsoCheckbox && enableSsoCheckbox.checked) {
                        setTimeout(() => {
                            if (typeof populateSsoFieldMappings === 'function') {
                                populateSsoFieldMappings();
                            }
                            if (typeof populateSsoDisabledFields === 'function') {
                                populateSsoDisabledFields();
                            }
                        }, 1000);
                    }
                }, 2000);
                
            }, 500);
        });
    } else {
        setTimeout(() => {
            enhanceSsoMappingPersistence();
            enhanceDynamicOptionsPersistence();
            enhanceSsoDisabledFieldsPersistence();
        }, 500);
    }
}

// Initialize the enhancements
initializePersistenceEnhancements();

console.log('🔧 Targeted form persistence enhancements loaded!');
