import { useState, useEffect } from "react"
import { useBroadcast, useBroadcastHistory } from "@/hooks/queries/use-broadcast"
import { AdvisoryPackage, NotificationChannel } from "@/types/broadcast"
import { useTeams } from "@/hooks/queries/use-teams"
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Checkbox } from "@/components/ui/checkbox"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Plus, Trash2, Megaphone, ShieldAlert, Users, Globe, Calculator, Send, History } from "lucide-react"
import { toast } from "sonner"
import { formatDistanceToNow } from "date-fns"

export default function Broadcasts() {
  const { mutateAsync: sendBroadcast, isPending } = useBroadcast()
  const { data: teams } = useTeams() // For team selection
  const { data: history, refetch: refetchHistory } = useBroadcastHistory()

  // Form State
  const [activeTab, setActiveTab] = useState<string>("announcement")
  
  // Announcement State
  const [announcementTarget, setAnnouncementTarget] = useState<"global" | "teams">("global")
  const [selectedTeams, setSelectedTeams] = useState<string[]>([])
  const [announcementSubject, setAnnouncementSubject] = useState("")
  const [announcementMessage, setAnnouncementMessage] = useState("")
  
  // Advisory State
  const [advisorySubject, setAdvisorySubject] = useState("")
  const [advisoryMessage, setAdvisoryMessage] = useState("")
  const [packages, setPackages] = useState<AdvisoryPackage[]>([
    { name: "", version: "", type: "" }
  ])
  
  // Impact Analysis State
  const [impactCount, setImpactCount] = useState<number | null>(null)
  const [impactProjectCount, setImpactProjectCount] = useState<number | null>(null)
  const [isCalculating, setIsCalculating] = useState(false)

  // Common State
  const [channels, setChannels] = useState<NotificationChannel[]>(["email"])

  // Clear impacts when tab changes or major inputs change
  useEffect(() => {
    setImpactCount(null)
    setImpactProjectCount(null)
  }, [activeTab, announcementTarget, packages, selectedTeams])

  const handleChannelToggle = (channel: NotificationChannel) => {
    setChannels(current => 
      current.includes(channel)
        ? current.filter(c => c !== channel)
        : [...current, channel]
    )
  }

  const addPackage = () => {
    setPackages([...packages, { name: "", version: "", type: "" }])
  }

  const removePackage = (index: number) => {
    setPackages(packages.filter((_, i) => i !== index))
  }

  const updatePackage = (index: number, field: keyof AdvisoryPackage, value: string) => {
    const newPackages = [...packages]
    newPackages[index] = { ...newPackages[index], [field]: value }
    setPackages(newPackages)
    setImpactCount(null) // invalidate calculation
  }

  const calculateImpact = async () => {
    setIsCalculating(true)
    try {
      if (activeTab === "announcement") {
         const result = await sendBroadcast({
            type: "general",
            target_type: announcementTarget,
            target_teams: announcementTarget === "teams" ? selectedTeams : undefined,
            subject: "Dry Run",
            message: "Dry Run",
            channels: [], // Doesn't matter for dry run
            dry_run: true
         })
         setImpactCount(result.recipient_count)
         setImpactProjectCount(0)
      } else {
         const validPackages = packages.filter(p => p.name.trim() !== "")
         if (validPackages.length === 0) return

         const result = await sendBroadcast({
            type: "advisory",
            target_type: "advisory",
            packages: validPackages,
            subject: "Dry Run",
            message: "Dry Run",
            channels: [],
            dry_run: true
         })
         setImpactCount(result.recipient_count) // usually 0 for advisory unless logic changes
         setImpactProjectCount(result.project_count || 0)
      }
    } catch (err) {
      // Error handling is done by mutation hook, but we can add specific logic here
    } finally {
      setIsCalculating(false)
    }
  }

  const handleSendAnnouncement = async () => {
    await sendBroadcast({
      type: "general",
      target_type: announcementTarget,
      target_teams: announcementTarget === "teams" ? selectedTeams : undefined,
      subject: announcementSubject,
      message: announcementMessage,
      channels: channels.length > 0 ? channels : undefined,
      dry_run: false
    })
    setImpactCount(null)
    toast.success("Announcement sent successfully")
    refetchHistory()
  }

  const handleSendAdvisory = async () => {
    // Filter out empty packages
    const validPackages = packages.filter(p => p.name.trim() !== "")
    
    await sendBroadcast({
      type: "advisory",
      target_type: "advisory",
      packages: validPackages,
      subject: advisorySubject,
      message: advisoryMessage,
      channels: channels.length > 0 ? channels : undefined,
      dry_run: false
    })
    setImpactCount(null)
    toast.success("Advisory broadcast sent successfully")
    refetchHistory()
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-start">
        <div>
           <h1 className="text-3xl font-bold tracking-tight">System Broadcasts</h1>
           <p className="text-muted-foreground">
           Send global announcements or targeted security advisories to users. Markdown is supported.
           </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList>
          <TabsTrigger value="announcement" className="flex items-center gap-2">
            <Megaphone className="h-4 w-4" />
            Announcement
          </TabsTrigger>
          <TabsTrigger value="advisory" className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" />
            Security Advisory
          </TabsTrigger>
          <TabsTrigger value="history" className="flex items-center gap-2">
            <History className="h-4 w-4" />
            History
          </TabsTrigger>
        </TabsList>
        
        {activeTab !== 'history' && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Channel Selection</CardTitle>
              <CardDescription>Force the message to be sent via selected channels (overrides user preferences)</CardDescription>
            </CardHeader>
          <CardContent className="flex gap-6">
             {["email", "slack", "mattermost", "teams"].map((c) => (
                <div key={c} className="flex items-center space-x-2">
                  <Checkbox 
                    id={`channel-${c}`} 
                    checked={channels.includes(c as NotificationChannel)}
                    onCheckedChange={() => handleChannelToggle(c as NotificationChannel)}
                  />
                  <Label htmlFor={`channel-${c}`} className="capitalize">{c}</Label>
                </div>
             ))}
          </CardContent>
        </Card>
        )}

        {/* ANNOUNCEMENT TAB */}
        <TabsContent value="announcement" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Create Announcement</CardTitle>
              <CardDescription>
                Send a general message to all users or specific teams.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Target Audience</Label>
                <div className="flex gap-4">
                  <Button
                    variant={announcementTarget === "global" ? "default" : "outline"}
                    onClick={() => setAnnouncementTarget("global")}
                    className="flex items-center gap-2"
                  >
                    <Globe className="h-4 w-4" />
                    All Users
                  </Button>
                  <Button
                    variant={announcementTarget === "teams" ? "default" : "outline"}
                    onClick={() => setAnnouncementTarget("teams")}
                    className="flex items-center gap-2"
                  >
                    <Users className="h-4 w-4" />
                    Specific Teams
                  </Button>
                </div>
              </div>

              {announcementTarget === "teams" && (
                <div className="space-y-2">
                  <Label>Select Teams</Label>
                  <Select
                     disabled={!!teams && selectedTeams.length > 0} 
                  >
                  </Select>
                   <div className="grid grid-cols-2 md:grid-cols-3 gap-2 border p-4 rounded-md h-40 overflow-y-auto">
                      {teams?.map((team) => (
                         <div key={team.id || team._id} className="flex items-center space-x-2">
                            <Checkbox 
                               id={`team-${team.id || team._id}`}
                               checked={selectedTeams.includes(team.id || team._id || '')}
                               onCheckedChange={(checked) => {
                                  const tid = team.id || team._id;
                                  if (!tid) return;
                                  if (checked) setSelectedTeams([...selectedTeams, tid])
                                  else setSelectedTeams(selectedTeams.filter(id => id !== tid))
                               }}
                            />
                            <Label htmlFor={`team-${team.id || team._id}`}>{team.name}</Label>
                         </div>
                      ))}
                   </div>
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="ann-subject">Subject</Label>
                <Input 
                  id="ann-subject" 
                  placeholder="e.g. Maintenance Scheduled for Tonight"
                  value={announcementSubject}
                  onChange={(e) => setAnnouncementSubject(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="ann-message">Message</Label>
                <Textarea 
                  id="ann-message" 
                  placeholder="Enter your message here..."
                  className="min-h-[150px]"
                  value={announcementMessage}
                  onChange={(e) => setAnnouncementMessage(e.target.value)}
                />
              </div>
              
            </CardContent>
            <CardFooter className="flex justify-between border-t p-6">
                <div className="flex items-center gap-4">
                    <Button variant="secondary" onClick={calculateImpact} disabled={isCalculating || (announcementTarget === 'teams' && selectedTeams.length === 0)}>
                        {isCalculating ? <span className="animate-spin mr-2">⏳</span> : <Calculator className="h-4 w-4 mr-2" />}
                        Calculate Reach
                    </Button>
                    {impactCount !== null && (
                        <div className="flex gap-2 items-center">
                            <Badge variant="outline" className="text-base px-3 py-1">
                                {impactCount} Users will be notified
                            </Badge>
                        </div>
                    )}
                </div>
                <Button 
                   onClick={handleSendAnnouncement} 
                   disabled={isPending || !announcementSubject || !announcementMessage || (announcementTarget === 'teams' && selectedTeams.length === 0)}
                >
                  <Send className="h-4 w-4 mr-2" />
                  Send Announcement
                </Button>
            </CardFooter>
          </Card>
        </TabsContent>

        {/* SECURITY ADVISORY TAB */}
        <TabsContent value="advisory" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Create Security Advisory</CardTitle>
              <CardDescription>
                Notify project owners who are using specific versions of dependencies.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                    <Label className="text-base">Affected Packages</Label>
                    <Button variant="outline" size="sm" onClick={addPackage}>
                        <Plus className="h-4 w-4 mr-2" />
                        Add Package
                    </Button>
                </div>
                
                {packages.map((pkg, index) => (
                    <div key={index} className="flex gap-3 items-end p-3 border rounded-md bg-muted/20">
                        <div className="flex-1 space-y-2">
                            <Label className="text-xs">Package Name</Label>
                            <Input 
                                placeholder="e.g. log4j-core" 
                                value={pkg.name}
                                onChange={(e) => updatePackage(index, 'name', e.target.value)}
                            />
                        </div>
                        <div className="w-32 space-y-2">
                            <Label className="text-xs">Max Version (&lt;=)</Label>
                            <Input 
                                placeholder="e.g. 2.14.0" 
                                value={pkg.version || ""}
                                onChange={(e) => updatePackage(index, 'version', e.target.value)}
                            />
                        </div>
                        <div className="w-32 space-y-2">
                            <Label className="text-xs">Type (Optional)</Label>
                            <Select 
                                value={pkg.type || ""} 
                                onValueChange={(val) => updatePackage(index, 'type', val)}
                            >
                                <SelectTrigger>
                                    <SelectValue placeholder="Any" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="maven">Maven</SelectItem>
                                    <SelectItem value="npm">NPM</SelectItem>
                                    <SelectItem value="pip">Pip</SelectItem>
                                    <SelectItem value="go">Go</SelectItem>
                                    <SelectItem value="nuget">NuGet</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <Button 
                            variant="ghost" 
                            size="icon" 
                            className="text-destructive hover:text-destructive"
                            onClick={() => removePackage(index)}
                            disabled={packages.length === 1}
                        >
                            <Trash2 className="h-4 w-4" />
                        </Button>
                    </div>
                ))}
              </div>

              <div className="space-y-2">
                <Label htmlFor="adv-subject">Advisory Subject</Label>
                <Input 
                  id="adv-subject" 
                  placeholder="e.g. Critical Vulnerability in Log4j"
                  value={advisorySubject}
                  onChange={(e) => setAdvisorySubject(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="adv-message">Advisory Details</Label>
                <Textarea 
                  id="adv-message" 
                  placeholder="Explain the vulnerability and recommended actions..."
                  className="min-h-[150px]"
                  value={advisoryMessage}
                  onChange={(e) => setAdvisoryMessage(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                    Note: A list of affected projects and dependencies will be automatically appended to the message for each recipient.
                </p>
              </div>

            </CardContent>
            <CardFooter className="flex justify-between border-t p-6">
                <div className="flex items-center gap-4">
                    <Button variant="secondary" onClick={calculateImpact} disabled={isCalculating || packages.every(p => !p.name)}>
                        {isCalculating ? <span className="animate-spin mr-2">⏳</span> : <Calculator className="h-4 w-4 mr-2" />}
                        Calculate Impact
                    </Button>
                    {impactProjectCount !== null && (
                        <Badge variant="destructive" className="text-base px-3 py-1">
                            {impactProjectCount} Projects Affected
                        </Badge>
                    )}
                </div>
                <Button 
                    variant="destructive"
                    onClick={handleSendAdvisory}
                    disabled={isPending || !advisorySubject || !advisoryMessage || packages.every(p => !p.name)}
                >
                  <ShieldAlert className="h-4 w-4 mr-2" />
                  Broadcast Security Advisory
                </Button>
            </CardFooter>
          </Card>
        </TabsContent>

        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>Broadcast History</CardTitle>
              <CardDescription>
                View previously sent announcements and security advisories.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                     <TableHead>Date</TableHead>
                     <TableHead>Subject</TableHead>
                     <TableHead>Type</TableHead>
                     <TableHead>Target</TableHead>
                     <TableHead>Reach</TableHead>
                     <TableHead>Creator</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                   {history?.map((item) => (
                      <TableRow key={item.id}>
                         <TableCell className="whitespace-nowrap">
                            {formatDistanceToNow(new Date(item.created_at), { addSuffix: true })}
                         </TableCell>
                         <TableCell className="font-medium">{item.subject}</TableCell>
                         <TableCell>
                            <Badge variant={item.type === 'advisory' ? 'destructive' : 'default'}>
                               {item.type}
                            </Badge>
                         </TableCell>
                         <TableCell>
                            <span className="capitalize text-muted-foreground">{item.target_type}</span>
                         </TableCell>
                         <TableCell>
                            <div className="flex flex-col text-xs gap-1">
                               <Badge variant="outline" className="w-fit">{item.unique_user_count || 0} Users</Badge>
                               {item.project_count > 0 && <span className="text-muted-foreground">{item.project_count} Projects</span>}
                            </div>
                         </TableCell>
                         <TableCell className="text-muted-foreground text-xs">{item.created_by}</TableCell>
                      </TableRow>
                   ))}
                   {(!history || history.length === 0) && (
                      <TableRow>
                         <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                            No broadcast history found.
                         </TableCell>
                      </TableRow>
                   )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
