<%#
kind: registration
name: Global Registration
model: ProvisioningTemplate
-%>
<%
    headers = ["-H 'Authorization: Bearer #{@auth_token}'"]
    activation_keys = [(@hostgroup.params['kt_activation_keys'] if @hostgroup), @activation_keys].compact.join(',')
-%>

# Rendered with following template parameters:
<%= "# User: [#{@user.login}]" -%>
<%= "\n# Organization: [#{@organization.name}]" if @organization -%>
<%= "\n# Location: [#{@location.name}]" if @location -%>
<%= "\n# Host group: [#{@hostgroup.title}]" if @hostgroup -%>
<%= "\n# Operating system: [#{@operatingsystem}]" if @operatingsystem -%>
<%= "\n# Setup Insights: [#{@setup_insights}]" unless @setup_insights.nil? -%>
<%= "\n# Setup remote execution: [#{@setup_remote_execution}]" unless @setup_remote_execution.nil? -%>
<%= "\n# Remote execution interface: [#{@remote_execution_interface}]" if @remote_execution_interface.present? -%>
<%= "\n# Packages: [#{@packages}]" if @packages.present? -%>
<%= "\n# Update packages: [#{@update_packages}]" unless @update_packages.nil? -%>
<%= "\n# Repository: [#{@repo}]" if @repo.present? -%>
<%= "\n# Repository GPG key URL: [#{@repo_gpg_key_url}]" if @repo_gpg_key_url.present? -%>
<%= "\n# Force: [#{@force}]" unless @force.nil? -%>
<%= "\n# Ignore subman errors: [#{@ignore_subman_errors}]" unless @ignore_subman_errors.nil? -%>
<%= "\n# Lifecycle environment id: [#{@lifecycle_environment_id}]" if @lifecycle_environment_id.present? -%>
<%= "\n# Activation keys: [#{activation_keys}]" if activation_keys.present? -%>



#need to see if the script is being ran elevated.
$checkadminrights = invoke-command -computername $env:COMPUTERNAME -command { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
if ($checkadminrights -ne $true)
    {
    Write-Output "Please run Elevated as and Administrator"
    Read-host "Press any key to exit"
    exit
    }


[string]$SSL_CA_CERT = <%= foreman_server_ca_cert %>


register_host() {
  curl --silent --show-error --cacert $SSL_CA_CERT --request POST <%= @registration_url %> \
       <%= headers.join(' ') %> \
       --data "host[name]=$(hostname --fqdn)" \
       --data "host[build]=false" \
       --data "host[managed]=false" \
<%= "       --data 'host[organization_id]=#{@organization.id}' \\\n" if @organization -%>
<%= "       --data 'host[location_id]=#{@location.id}' \\\n" if @location -%>
<%= "       --data 'host[hostgroup_id]=#{@hostgroup.id}' \\\n" if @hostgroup -%>
<%= "       --data 'host[operatingsystem_id]=#{@operatingsystem.id}' \\\n" if @operatingsystem -%>
<%= "       --data host[interfaces_attributes][0][identifier]=#{shell_escape(@remote_execution_interface)} \\\n" if @remote_execution_interface.present? -%>
#<%= "       --data 'setup_insights=#{@setup_insights}' \\\n" unless @setup_insights.nil? -%>
#<%= "       --data 'setup_remote_execution=#{@setup_remote_execution}' \\\n" unless @setup_remote_execution.nil? -%>
#<%= "       --data remote_execution_interface=#{shell_escape(@remote_execution_interface)} \\\n" if @remote_execution_interface.present? -%>
#<%= "       --data packages=#{shell_escape(@packages)} \\\n" if @packages.present? -%>
#<%= "       --data 'update_packages=#{@update_packages}' \\\n" unless @update_packages.nil? -%>

}

echo "#"
echo "# Running registration"
echo "#"

####need to update this
register_host | bash
<% end -%>
