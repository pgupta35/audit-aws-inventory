# ACM
#   - list_certificates
#     - id: certificate_summary_list.certificate_arn
coreo_aws_rule "acm-inventory-certificates" do
  service :ACM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ACM Inventory"
  description "This rule performs an inventory on the ACM service using the list_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_certificates"]
  audit_objects ["object.certificate_summary_list.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificate_summary_list.certificate_arn"]
end
  
coreo_aws_rule_runner "acm-inventory-runner" do
  action :run
  service :ACM
  rules ${AUDIT_AWS_ACM_ALERT_LIST}
end
# ACM
#   - list_certificates
#     - id: certificate_summary_list.certificate_arn
coreo_aws_rule "acm-inventory-certificates" do
  service :ACM
  action :define
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "ACM Inventory"
  description "This rule performs an inventory on the ACM service using the list_certificates function"
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["list_certificates"]
  audit_objects ["object.certificate_summary_list.certificate_arn"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.certificate_summary_list.certificate_arn"]
end
  
coreo_aws_rule_runner "acm-inventory-runner" do
  action :run
  service :ACM
  rules ${AUDIT_AWS_ACM_ALERT_LIST}
end
