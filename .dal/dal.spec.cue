#Player: "claude" | "codex" | "gemini"
#Role:   "leader" | "member"
#DalProfile: {
	uuid!:    string & != ""
	name!:    string & != ""
	version!: string
	player!:  #Player
	role!:    #Role
	skills?:  [...string]
	hooks?:   [...string]
	git? {
		user:         string
		email:        string
		github_token: string
	}
	auto_task?:      string
	auto_interval?:  string
	player_version?: string
}
