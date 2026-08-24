from django.urls import path
from . import views
from .views import *

urlpatterns = [
    # path('dashboard/', DashboardView.as_view(), name='dashboard'),  #to remove
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
 
    
    
    path('', publicHomeView.as_view(), name='publichome'),
    path('home/', HomePageView.as_view(), name='home'),
    path('initiatives/', InitiativesView.as_view(), name='initiatives'),
    path('admin/', AdminView.as_view(), name='admin'),
    path('settings/', SettingsView.as_view(), name='settings'),
    
    # Configurations
    path('configurations/', ConfigurationsView.as_view(), name='configurations'),
    path('pmweb/configurations/', ConfigurationsView.as_view(), name='pmweb_configurations'),
    
    # Database Connections
    path('configurations/database-connections/', DatabaseConnectionsView.as_view(), name='database_connections'),
    path('configurations/database-connection/<int:connection_id>/', DatabaseConnectionDetailView.as_view(), name='database_connection_detail'),
    path('configurations/test-database-connection/', TestDatabaseConnectionView.as_view(), name='test_database_connection'),
    path('configurations/save-database-connection/', SaveDatabaseConnectionView.as_view(), name='save_database_connection'),
    path('configurations/saved-queries/', SavedQueriesView.as_view(), name='saved_queries'),
    path('configurations/saved-query/<int:query_id>/', SavedQueryDetailView.as_view(), name='saved_query_detail'),
    path('configurations/run-query/', RunQueryView.as_view(), name='run_query'),
    path('configurations/save-query/', SaveQueryView.as_view(), name='save_query'),
    path('configurations/run-saved-query/<int:query_id>/', RunSavedQueryView.as_view(), name='run_saved_query'),
    
    # Stored Procedures
    path('configurations/stored-procedures/<int:connection_id>/', StoredProceduresView.as_view(), name='stored_procedures'),
    path('configurations/procedure-parameters/<int:connection_id>/<str:procedure_id>/', ProcedureParametersView.as_view(), name='procedure_parameters'),
    path('configurations/execute-procedure/', ExecuteProcedureView.as_view(), name='execute_procedure'),
    path('configurations/approved-procedures/', ApprovedProcedureManagementView.as_view(), name='approved_procedures'),
    path('configurations/approved-procedures/api/', ApprovedProcedureCollectionView.as_view(), name='approved_procedure_collection'),
    path('configurations/approved-procedures/<int:approval_id>/', ApprovedProcedureManagementDetailView.as_view(), name='approved_procedure_management_detail'),
    path('configurations/approved-procedures/<int:approval_id>/api/', ApprovedProcedureDetailView.as_view(), name='approved_procedure_detail'),
    path('configurations/approved-procedures/<int:approval_id>/toggle/', ApprovedProcedureToggleView.as_view(), name='approved_procedure_toggle'),
    path('configurations/approved-procedures/<int:approval_id>/parameters/', ApprovedProcedureParametersView.as_view(), name='approved_procedure_parameters'),
    path('configurations/approved-procedures/<int:approval_id>/audits/', ApprovedProcedureAuditHistoryView.as_view(), name='approved_procedure_audits'),
    path('configurations/save-procedure-execution/', SaveProcedureExecutionView.as_view(), name='save_procedure_execution'),
    path('configurations/saved-procedure-executions/', SavedProcedureExecutionsView.as_view(), name='saved_procedure_executions'),
    
    path('manage-forms/', ManageFormsView.as_view(), name='manage_forms'),
    path('create-forms/', CreateFormsView.as_view(), name='create_forms'),
    path('generate-form/', CreateFrom.as_view(), name='generate_form'),
    path('debug-auth/', views.debug_auth, name='debug_auth'),
    path('fetch-database-data/', views.FetchDatabaseDataView.as_view(), name='fetch_database_data'),
    path('edit-form/<uuid:uuid>/', EditFormView.as_view(), name='edit_form'),
    path('forms/<str:form_name>/preview/', views.PreviewTemplateView.as_view(), name='preview_template'),
    path('view-forms-submissions/', ViewFormSubmissionsView.as_view(), name='view_form_submissions'),
    path('view-form-submissions/<uuid:uuid>/', OpenFormSubmissionsView.as_view(), name='open_form_submissions'),
    path('fill-form/<uuid:uuid>/', FillFormView.as_view(), name='fill_form'),
    path('submit-form/<uuid:uuid>/', SubmitFormView.as_view(), name='submit_form'),
    path('forms/delete/<uuid:uuid>/', DeleteFormView.as_view(), name='delete_form'),
    
    # SSO Integration Test
    path('sso-test/', SSOTestView.as_view(), name='sso_test'),
    
    path('submission-details/<str:uuid>/', submissionDetails.as_view(), name='submission_details'),
    path('files/<int:file_id>/download/', FileUploadDownloadView.as_view(), name='download_submission_file'),
    
    
    # user side urls
    path('my-submissions/<uuid:uuid>/', user_OpenFormSubmissionsView.as_view(), name='my_submissions'),
    path('submission-details-user/<str:uuid>/', user_submissionDetails.as_view(), name='user_submission_details'),
    
    
    # Users add
    path('users/view/', UserListView.as_view(), name='users_view'),
    path('users/add/', AddOrUpdateUserView.as_view(), name='add_user'),
    path('users/update/<int:user_id>/', AddOrUpdateUserView.as_view(), name='update_user'),
    path('users/detail/<int:user_id>/', UserDetailView.as_view(), name='user_detail'),
    path('users/delete/<int:user_id>/', DeleteUserView.as_view(), name='delete_user'),
    path('users/search/', SearchUserView.as_view(), name='search_user'),

    
    
    # -- integration
    path('integrations/', IntegrationsView.as_view(), name='integrations'),
    path('integrations/<int:integration_id>/fields/', FetchIntegrationFieldsView.as_view(), name='fetch_integration_fields'),
    path('integrations/save/', SaveIntegrationCredentialView.as_view(), name='save_api_credentials'),
    path('integrations/toggle/', ToggleIntegrationView.as_view(), name='toggle_integration'),  # New URL

    
    # form permission
    path('permissions/', views.PermissionsView.as_view(), name='permissions'), # For initial page load
    path('permissions/data/', views.PermissionsDataView.as_view(), name='permissions_data'), # New URL for DataTable data
    path('permissions/save/', views.PermissionsSaveView.as_view(), name='save_permissions'), # New URL for saving permissions
    path('permissions/edit/<int:permission_id>/', views.EditPermissionView.as_view(), name='edit_permission'),
    path('permissions/refresh-cache/', views.RefreshCacheView.as_view(), name='refresh_cache'), # New URL for cache refresh
    path('permissions/delete/<int:permission_id>/', DeletePermissionView.as_view(), name='delete_permission'),
    
    
    
    # path('microsoft-db/', views.microsoft_db_data, name='microsoft_db_data'),
    path('initiatives/', InitiativesView.as_view(), name='initiatives'),
     path('fetch-table-data/', views.FetchTableDataView.as_view(), name='fetch_table_data'),

    
    # test rest api
    path('testapi/', views.testapi, name='testapi'),
    
    # SSO provider info API
    path('api/sso-provider-info/', views.SSOProviderInfoView.as_view(), name='sso_provider_info'),

]
