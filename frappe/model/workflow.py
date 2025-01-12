# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
import frappe
from frappe.utils import cint
from frappe import _
from six import string_types
import json
from frappe.utils import now

class WorkflowStateError(frappe.ValidationError): pass
class WorkflowTransitionError(frappe.ValidationError): pass
class WorkflowPermissionError(frappe.ValidationError): pass

def get_workflow_name(doctype):
	workflow_name = frappe.cache().hget('workflow', doctype)
	if workflow_name is None:
		workflow_name = frappe.db.get_value("Workflow", {"document_type": doctype,
			"is_active": 1}, "name")
		frappe.cache().hset('workflow', doctype, workflow_name or '')

	return workflow_name

@frappe.whitelist()
def get_transitions(doc, workflow = None, raise_exception=False, ignore_role_check=False):
	'''Return list of possible transitions for the given doc'''
	doc = frappe.get_doc(frappe.parse_json(doc))

	if doc.is_new():
		return []

	doc.load_from_db()

	frappe.has_permission(doc, 'read', throw=True)
	roles = frappe.get_roles()

	if not workflow:
		workflow = get_workflow(doc.doctype)
	current_state = doc.get(workflow.workflow_state_field)

	if not current_state:
		if raise_exception:
			raise WorkflowStateError
		else:
			frappe.throw(_('Workflow State not set'), WorkflowStateError)

	transitions = []
	for transition in workflow.transitions:
		if transition.state == current_state and (transition.allowed in roles or ignore_role_check):
			if not is_transition_condition_satisfied(transition, doc):
				continue
			transitions.append(transition.as_dict())
	return transitions

def get_workflow_safe_globals():
	# access to frappe.db.get_value, frappe.db.get_list, and date time utils.
	return dict(
		frappe=frappe._dict(
			db=frappe._dict(get_value=frappe.db.get_value, get_list=frappe.db.get_list),
			session=frappe.session,
			utils=frappe._dict(
				now_datetime=frappe.utils.now_datetime,
				add_to_date=frappe.utils.add_to_date,
				get_datetime=frappe.utils.get_datetime,
				now=frappe.utils.now,
			),
		)
	)

def is_transition_condition_satisfied(transition, doc):
	if not transition.condition:
		return True
	else:
		return frappe.safe_eval(transition.condition, get_workflow_safe_globals(), dict(doc=doc.as_dict()))


def set_workflow_history(doc,performed_by, method, reason):
	workflow_history = frappe.new_doc("Workflow History")
	workflow_history.parent = doc.name
	workflow_history.parenttype = doc.doctype
	workflow_history.parentfield = "workflow_history"
	workflow_history.parentfield = "workflow_history"
	if performed_by and doc.workflow_status in ('PO accepted by Buyer', 'PO rejected by Buyer', 'PO accepted by Seller', 'PO rejected by Seller', 'Proforma Invoice Accepted by Buyer', 'Proforma Invoice rejected by Buyer', 'Final Invoice Accepted by Buyer', 'Final Invoice rejected by Buyer'):
		workflow_history.updated_by =  performed_by
	else:
		workflow_history.updated_by = frappe.session.user
	workflow_history.idx = 1
	if doc.doctype == "Purchase Order":
		workflow_history.workflow_status =  doc.workflow_status
	else:
		workflow_history.workflow_status =  doc.status
	frappe.logger("abcd").debug("aaaaaaaaaaaaaaa")
	workflow_history.flags.ignore_permissions = True
	workflow_history.insert()
	#frappe.db.commit()
	frappe.logger("abcd").debug(f"bbbbbbbbbbbbbbbbb: {workflow_history}")

@frappe.whitelist()
def apply_workflow(doc, action, rejection_reason=None,performed_by=None):
	return custom_apply_workflow(doc, action, rejection_reason,performed_by,ignore_role_check=False)

def custom_apply_workflow(doc, action, rejection_reason=None,performed_by=None,ignore_role_check=False):
	'''Allow workflow action on the current doc'''
	# doc = frappe.get_doc(frappe.parse_json(doc))
	try:

		parsed_json =  frappe.parse_json(doc)
		doc = frappe.get_doc(parsed_json.get("doctype"), parsed_json.get("name"))
		workflow = get_workflow(doc.doctype)
		transitions = get_transitions(doc, workflow, ignore_role_check=ignore_role_check)
		user = frappe.session.user

		# find the transition
		transition = None
		for t in transitions:
			if t.action == action:
				transition = t
		frappe.logger("testlog").debug(f"8888888888888888888888888888888888888888action: {action}")
		if not transition:
			frappe.throw(_("Not a valid Workflow Action"), WorkflowTransitionError)

		if not has_approval_access(user, doc, transition):
			frappe.throw(_("Self approval is not allowed"))

		# update workflow state field
		doc.set(workflow.workflow_state_field, transition.next_state)
		set_workflow_history(doc,performed_by, None, rejection_reason)
		if doc.doctype == "Customer" and  doc.status ==  "Verified":
			verify_time_date=str(now())
			verify_split=verify_time_date.split(" ")
			doc.set("verification_date",verify_split[0])
			doc.set("verification_time",verify_split[1])
		# find settings for the next state
		next_state = [d for d in workflow.states if d.state == transition.next_state][0]


		if(transition.next_state  ==  "Rejected"):
			doc.set("rejection_reason", rejection_reason)
		
		frappe.logger('testlog').debug("aaaaaaaaaaaaaaa 1111111111111")
		if doc.doctype == "Purchase Order":
			frappe.logger('testlog').debug("1111111111111111111111")
			if(transition.next_state  ==  "GRN rejected by Finance"):
				frappe.logger('testlog').debug("222222222222222222222")
				doc.set("grn_rejection_reason", rejection_reason)
				frappe.logger('testlog').debug(f"grn_rejection_reaosn: {doc.grn_rejection_reason}, resje: {rejection_reason}")
		# update any additional field
		if next_state.update_field:
			doc.set(next_state.update_field, next_state.update_value)
 
		new_docstatus = cint(next_state.doc_status)
		if doc.docstatus == 0 and new_docstatus == 0:
			doc.flags.ignore_permissions = True
			doc.save()
		elif doc.docstatus == 0 and new_docstatus == 1:
			doc.flags.ignore_permissions = True
			doc.submit()
		elif doc.docstatus == 1 and new_docstatus == 1:
			doc.flags.ignore_permissions = True
			doc.save()
		elif doc.docstatus == 1 and new_docstatus == 2:
			doc.flags.ignore_permissions = True
			doc.cancel()
		else:
			frappe.throw(_('Illegal Document Status for {0}').format(next_state.state))

		doc.add_comment('Workflow', _(next_state.state))

		if doc.doctype == "Purchase Order":
			doc = apply_auto_workflow(doc, workflow,rejection_reason,performed_by)

		return doc
	except Exception as e:
		frappe.logger('testlog').debug(frappe.get_traceback())
		frappe.db.rollback()
		#frappe.db.begin()
		#doc.db_set("razor_customer_id", "abcdxyz")
		#frappe.db.commit()
		frappe.db.begin()
		raise e
	finally:
		frappe.logger("finally_logs").debug(f"------------------ In Finally logs --- ")
		
		if getattr(frappe.local, 'custom_razor_customer_id', None):
			frappe.logger("finally_logs").debug(f"setting razor customer_id to rid: {getattr(frappe.local, 'custom_razor_customer_id', None)}")
			doc.db_set("razor_customer_id", getattr(frappe.local, 'custom_razor_customer_id', None))
		if getattr(frappe.local, 'custom_razor_customer_response', None):
			frappe.logger("finally_logs").debug(f"setting razor customer response: {getattr(frappe.local, 'custom_razor_customer_response', None)}")
			doc.db_set("razor_customer_response", getattr(frappe.local, 'custom_razor_customer_response', None))
		# virtual account response attributes
		if getattr(frappe.local, 'custom_virtual_account_response', None):
			doc.db_set("virtual_account_response", getattr(frappe.local, 'custom_virtual_account_response', None))
		if getattr(frappe.local, 'custom_va_id', None):
			doc.db_set("va_id", getattr(frappe.local, 'custom_va_id', None))
		if getattr(frappe.local, 'custom_receiver_ifsc', None):
			doc.db_set("receiver_ifsc", getattr(frappe.local, 'custom_receiver_ifsc', None))
		if getattr(frappe.local, 'custom_receiver_bank_name', None):
			doc.db_set("receiver_bank_name", getattr(frappe.local, 'custom_receiver_bank_name', None))
		if getattr(frappe.local, 'custom_receiver_name', None):
			doc.db_set("receiver_name", getattr(frappe.local, 'custom_receiver_name', None))
		if getattr(frappe.local, 'custom_receiver_account_number', None):
			doc.db_set("receiver_account_number", getattr(frappe.local, 'custom_receiver_account_number', None))
		if getattr(frappe.local, 'custom_receiver_id', None):
			doc.db_set("receiver_id", getattr(frappe.local, 'custom_receiver_id', None))
		if getattr(frappe.local, 'custom_entity', None):
			doc.db_set("entity", getattr(frappe.local, 'custom_entity', None))
		if getattr(frappe.local, 'custom_receiver_username', None):
			doc.db_set("receiver_username", getattr(frappe.local, 'custom_receiver_username', None))
		if getattr(frappe.local, 'custom_receiver_handle', None):
			doc.db_set("receiver_handle", getattr(frappe.local, 'custom_receiver_handle', None))
		if getattr(frappe.local, 'custom_receiver_address', None):
			doc.db_set("receiver_address", getattr(frappe.local, 'custom_receiver_address', None))
		frappe.db.commit()
		frappe.db.begin()

def apply_auto_workflow(doc, workflow,rejection_reason=None, performed_by=None):
	next_workflow_action = None
	if doc.workflow_status == "Proforma Invoice Accepted by Buyer":
		if doc.received_quantity and doc.goods_received_notee and (doc.rejection_quantity or int(doc.rejection_quantity) == 0) and doc.final_quantity:
			next_workflow_action = "Upload GRN"

	if doc.workflow_status == "PO accepted by Buyer":
		next_workflow_action = "Send PO to Seller"

	if not next_workflow_action: return doc
	user = frappe.session.user
	
	current_state = doc.get(workflow.workflow_state_field)

	frappe.has_permission(doc, 'read', throw=True)
	roles = frappe.get_roles()
	
	transitions = []
	for transition in workflow.transitions:
		if transition.state == current_state and (transition.allowed in roles or ignore_role_check):
			if not is_transition_condition_satisfied(transition, doc):
				continue
			transitions.append(transition.as_dict())
	
	transition = None
	for t in transitions:
		if t.action == next_workflow_action:
			transition = t

	if not transition:
		frappe.throw(_("Not a valid Workflow Action"), WorkflowTransitionError)

	if not has_approval_access(user, doc, transition):
		frappe.throw(_("Self approval is not allowed"))

	# update workflow state field
	doc.set(workflow.workflow_state_field, transition.next_state)
	set_workflow_history(doc,performed_by, None, rejection_reason)


	# find settings for the next state
	next_state = [d for d in workflow.states if d.state == transition.next_state][0]


	if(transition.next_state  ==  "Rejected"):
		doc.set("rejection_reason", rejection_reason)

	if doc.doctype == "Purchase Order":
		if(transition.next_state  ==  "GRN rejected by Finance"):
			doc.set("grn_rejection_reason", rejection_reason)

	# update any additional field
	if next_state.update_field:
		doc.set(next_state.update_field, next_state.update_value)

	new_docstatus = cint(next_state.doc_status)
	if doc.docstatus == 0 and new_docstatus == 0:
		doc.flags.ignore_permissions = True
		doc.save()
	elif doc.docstatus == 0 and new_docstatus == 1:
		doc.flags.ignore_permissions = True
		doc.submit()
	elif doc.docstatus == 1 and new_docstatus == 1:
		doc.flags.ignore_permissions = True
		doc.save()
	elif doc.docstatus == 1 and new_docstatus == 2:
		doc.flags.ignore_permissions = True
		doc.cancel()
	else:
		frappe.throw(_('Illegal Document Status for {0}').format(next_state.state))

	doc.add_comment('Workflow', _(next_state.state))

	return doc


@frappe.whitelist()
def can_cancel_document(doctype):
	workflow = get_workflow(doctype)
	for state_doc in workflow.states:
		if state_doc.doc_status == '2':
			for transition in workflow.transitions:
				if transition.next_state == state_doc.state:
					return False
			return True
	return True

def validate_workflow(doc):
	'''Validate Workflow State and Transition for the current user.

	- Check if user is allowed to edit in current state
	- Check if user is allowed to transition to the next state (if changed)
	'''
	workflow = get_workflow(doc.doctype)

	current_state = None
	if getattr(doc, '_doc_before_save', None):
		current_state = doc._doc_before_save.get(workflow.workflow_state_field)
	next_state = doc.get(workflow.workflow_state_field)

	if not next_state:
		next_state = workflow.states[0].state
		doc.set(workflow.workflow_state_field, next_state)

	if not current_state:
		current_state = workflow.states[0].state

	state_row = [d for d in workflow.states if d.state == current_state]
	if not state_row:
		frappe.throw(_('{0} is not a valid Workflow State. Please update your Workflow and try again.').format(frappe.bold(current_state)))
	state_row = state_row[0]

	# if transitioning, check if user is allowed to transition
	if current_state != next_state:
		bold_current = frappe.bold(current_state)
		bold_next = frappe.bold(next_state)

		if not doc._doc_before_save:
			# transitioning directly to a state other than the first
			# e.g from data import
			frappe.throw(_('Workflow State transition not allowed from {0} to {1}').format(bold_current, bold_next),
				WorkflowPermissionError)


		transitions = get_transitions(doc._doc_before_save)

		transition = [d for d in transitions if d.next_state == next_state]

		if doc.doctype == "Purchase Order" and not transition:
			if next_state == "GRN Uploaded by Fse" and (current_state == "Proforma Invoice Sent to Buyer"):
				return
			if next_state == "PO sent to Seller" and (current_state == "PO sent to Buyer"):
				return

		if not transition:
			frappe.throw(_('Workflow State transition not allowed from {0} to {1}').format(bold_current, bold_next),
				WorkflowPermissionError)

def get_workflow(doctype):
	return frappe.get_doc('Workflow', get_workflow_name(doctype))

def has_approval_access(user, doc, transition):
	return (user == 'Administrator'
		or transition.get('allow_self_approval')
		or user != doc.get('owner'))

def get_workflow_state_field(workflow_name):
	return get_workflow_field_value(workflow_name, 'workflow_state_field')

def send_email_alert(workflow_name):
	return get_workflow_field_value(workflow_name, 'send_email_alert')

def get_workflow_field_value(workflow_name, field):
	value = frappe.cache().hget('workflow_' + workflow_name, field)
	if value is None:
		value = frappe.db.get_value("Workflow", workflow_name, field)
		frappe.cache().hset('workflow_' + workflow_name, field, value)
	return value

@frappe.whitelist()
def bulk_workflow_approval(docnames, doctype, action):
	from collections import defaultdict

	# dictionaries for logging
	failed_transactions = defaultdict(list)
	successful_transactions = defaultdict(list)

	# WARN: message log is cleared
	print("Clearing frappe.message_log...")
	frappe.clear_messages()

	docnames = json.loads(docnames)
	for (idx, docname) in enumerate(docnames, 1):
		message_dict = {}
		try:
			show_progress(docnames, _('Applying: {0}').format(action), idx, docname)
			apply_workflow(frappe.get_doc(doctype, docname), action)
			frappe.db.commit()
		except Exception as e:
			if not frappe.message_log:
				# Exception is  raised manually and not from msgprint or throw
				message = "{0}".format(e.__class__.__name__)
				if e.args:
					message +=  " : {0}".format(e.args[0])
				message_dict = {"docname": docname, "message": message}
				failed_transactions[docname].append(message_dict)

			frappe.db.rollback()
			frappe.log_error(frappe.get_traceback(), "Workflow {0} threw an error for {1} {2}".format(action, doctype, docname))
		finally:
			if not message_dict:
				if frappe.message_log:
					messages = frappe.get_message_log()
					for message in messages:
						frappe.message_log.pop()
						message_dict = {"docname": docname, "message": message.get("message")}

						if message.get("raise_exception", False):
							failed_transactions[docname].append(message_dict)
						else:
							successful_transactions[docname].append(message_dict)
				else:
					successful_transactions[docname].append({"docname": docname, "message": None})

	if failed_transactions and successful_transactions:
		indicator = "orange"
	elif failed_transactions:
		indicator  = "red"
	else:
		indicator = "green"

	print_workflow_log(failed_transactions, _("Failed Transactions"), doctype, indicator)
	print_workflow_log(successful_transactions, _("Successful Transactions"), doctype, indicator)

def print_workflow_log(messages, title, doctype, indicator):
	if messages.keys():
		msg = "<h4>{0}</h4>".format(title)

		for doc in messages.keys():
			if len(messages[doc]):
				html = "<details><summary>{0}</summary>".format(frappe.utils.get_link_to_form(doctype, doc))
				for log in messages[doc]:
					if log.get('message'):
						html += "<div class='small text-muted' style='padding:2.5px'>{0}</div>".format(log.get('message'))
				html += "</details>"
			else:
				html = "<div>{0}</div>".format(doc)
			msg += html

		frappe.msgprint(msg, title=_("Workflow Status"), indicator=indicator, is_minimizable=True)

@frappe.whitelist()
def get_common_transition_actions(docs, doctype):
	common_actions = []
	if isinstance(docs, string_types):
		docs = json.loads(docs)
	try:
		for (i, doc) in enumerate(docs, 1):
			if not doc.get('doctype'):
				doc['doctype'] = doctype
			actions = [t.get('action') for t in get_transitions(doc, raise_exception=True) \
				if has_approval_access(frappe.session.user, doc, t)]
			if not actions:
				return []
			common_actions = actions if i == 1 else set(common_actions).intersection(actions)
			if not common_actions:
				return []
	except WorkflowStateError:
		pass

	return list(common_actions)

def show_progress(docnames, message, i, description):
	n = len(docnames)
	if n >= 5:
		frappe.publish_progress(
			float(i) * 100 / n,
			title = message,
			description = description
		)

def set_workflow_state_on_action(doc, workflow_name, action):
	workflow = frappe.get_doc('Workflow', workflow_name)
	workflow_state_field = workflow.workflow_state_field

	# If workflow state of doc is already correct, don't set workflow state
	for state in workflow.states:
		if state.state == doc.get(workflow_state_field) and doc.docstatus == cint(state.doc_status):
			return

	action_map = {
		'update_after_submit': '1',
		'submit': '1',
		'cancel': '2'
	}
	docstatus = action_map[action]
	for state in workflow.states:
		if state.doc_status == docstatus:
			doc.set(workflow_state_field, state.state)
			return
