package postman

var roleDescriptions = map[string]string{
	"super-admin":       "(Enterprise Only) Manages everything within a team, including team settings, members, roles, and resources. This role can view and manage all elements in public, team, private, and personal workspaces. Super Admins can perform all actions that other roles can perform.",
	"admin":             "Manages team members and team settings. Can also view monitor metadata and run, pause, and resume monitors.",
	"billing":           "Manages team plan and payments. Billing roles can be granted by a Super Admin, Team Admin, or by a fellow team member with a Billing role.",
	"user":              "Has access to all team resources and workspaces.",
	"community-manager": "(Pro & Enterprise Only) Manages the public visibility of workspaces and team profile.",
	"partner-manager":   "(Internal, Enterprise plans only) - Manages all Partner Workspaces within an organization. Controls Partner Workspace settings and visibility, and can send invites to partners.",
	"partner":           "(External, Professional and Enterprise plans only) - All partners are automatically granted the Partner role at the team level. Partners can only access the Partner Workspaces they've been invited to.",
	"guest":             "Views collections and sends requests in collections that have been shared with them. This role can't be directly assigned to a user.",
	"flow-editor":       "(Basic and Professional plans only) - Can create, edit, run, and publish Postman Flows.",
}
