import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getTeams, createTeam, addTeamMember, deleteTeam, Team } from '@/lib/api';
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Plus, Users as UsersIcon, UserPlus, Trash2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

import { Spinner } from '@/components/ui/spinner';

export default function TeamsPage() {
  const queryClient = useQueryClient();
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isAddMemberOpen, setIsAddMemberOpen] = useState(false);
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState<string | null>(null);
  const [teamToDelete, setTeamToDelete] = useState<string | null>(null);

  // Create Team Form State
  const [newTeamName, setNewTeamName] = useState('');
  const [newTeamDesc, setNewTeamDesc] = useState('');

  // Add Member Form State
  const [newMemberEmail, setNewMemberEmail] = useState('');
  const [newMemberRole, setNewMemberRole] = useState('member');

  const { data: teams, isLoading, error } = useQuery({
    queryKey: ['teams'],
    queryFn: getTeams,
  });

  const createTeamMutation = useMutation({
    mutationFn: (data: { name: string; description: string }) => createTeam(data.name, data.description),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
      setIsCreateOpen(false);
      setNewTeamName('');
      setNewTeamDesc('');
    },
  });

  const addMemberMutation = useMutation({
    mutationFn: (data: { teamId: string; email: string; role: string }) => addTeamMember(data.teamId, data.email, data.role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
      setIsAddMemberOpen(false);
      setNewMemberEmail('');
      setNewMemberRole('member');
      setSelectedTeamId(null);
    },
  });

  const deleteTeamMutation = useMutation({
    mutationFn: (teamId: string) => deleteTeam(teamId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
      setIsDeleteConfirmOpen(false);
      setTeamToDelete(null);
    },
  });

  const handleCreateTeam = (e: React.FormEvent) => {
    e.preventDefault();
    createTeamMutation.mutate({ name: newTeamName, description: newTeamDesc });
  };

  const handleAddMember = (e: React.FormEvent) => {
    e.preventDefault();
    if (selectedTeamId) {
      addMemberMutation.mutate({ teamId: selectedTeamId, email: newMemberEmail, role: newMemberRole });
    }
  };

  const handleDeleteClick = (teamId: string) => {
      setTeamToDelete(teamId);
      setIsDeleteConfirmOpen(true);
  }

  const confirmDelete = () => {
      if (teamToDelete) {
          deleteTeamMutation.mutate(teamToDelete);
      }
  }

  const openAddMemberDialog = (teamId: string) => {
    setSelectedTeamId(teamId);
    setIsAddMemberOpen(true);
  };

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Spinner size={48} />
      </div>
    );
  }

  if (error) {
    return <div className="text-red-500">Error loading teams</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Teams</h1>
        <Dialog open={isCreateOpen} onOpenChange={setIsCreateOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create Team
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[425px]">
            <form onSubmit={handleCreateTeam}>
              <DialogHeader>
                <DialogTitle>Create Team</DialogTitle>
                <DialogDescription>
                  Create a new team to manage projects and members.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="name" className="text-right">
                    Name
                  </Label>
                  <Input
                    id="name"
                    value={newTeamName}
                    onChange={(e) => setNewTeamName(e.target.value)}
                    className="col-span-3"
                    required
                  />
                </div>
                <div className="grid grid-cols-4 items-center gap-4">
                  <Label htmlFor="description" className="text-right">
                    Description
                  </Label>
                  <Input
                    id="description"
                    value={newTeamDesc}
                    onChange={(e) => setNewTeamDesc(e.target.value)}
                    className="col-span-3"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button type="submit" disabled={createTeamMutation.isPending}>
                    {createTeamMutation.isPending ? 'Creating...' : 'Create Team'}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {teams?.map((team: Team) => (
          <Card key={team._id} className="flex flex-col">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                {team.name}
              </CardTitle>
              <div className="flex items-center gap-2">
                  <UsersIcon className="h-4 w-4 text-muted-foreground" />
                  <Button variant="ghost" size="icon" className="h-6 w-6 text-destructive hover:text-destructive/90" onClick={() => handleDeleteClick(team._id)}>
                      <Trash2 className="h-4 w-4" />
                  </Button>
              </div>
            </CardHeader>
            <CardContent className="flex-1">
              <div className="text-2xl font-bold">{team.members.length} Members</div>
              <p className="text-xs text-muted-foreground mt-1">
                {team.description || "No description"}
              </p>
              <div className="mt-4 space-y-1">
                  {team.members.slice(0, 3).map(member => (
                      <div key={member.user_id} className="text-xs flex justify-between">
                          <span className="truncate max-w-[150px]">{member.username || member.user_id}</span>
                          <span className="text-muted-foreground capitalize">{member.role}</span>
                      </div>
                  ))}
                  {team.members.length > 3 && (
                      <div className="text-xs text-muted-foreground">
                          + {team.members.length - 3} more
                      </div>
                  )}
              </div>
            </CardContent>
            <CardFooter>
                <Button variant="outline" className="w-full" onClick={() => openAddMemberDialog(team._id)}>
                    <UserPlus className="mr-2 h-4 w-4" />
                    Add Member
                </Button>
            </CardFooter>
          </Card>
        ))}
      </div>

      <Dialog open={isAddMemberOpen} onOpenChange={setIsAddMemberOpen}>
        <DialogContent className="sm:max-w-[425px]">
          <form onSubmit={handleAddMember}>
            <DialogHeader>
              <DialogTitle>Add Team Member</DialogTitle>
              <DialogDescription>
                Add a user to the team by their email address.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="email" className="text-right">
                  Email
                </Label>
                <Input
                  id="email"
                  type="email"
                  value={newMemberEmail}
                  onChange={(e) => setNewMemberEmail(e.target.value)}
                  className="col-span-3"
                  required
                />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="role" className="text-right">
                  Role
                </Label>
                <div className="col-span-3">
                    <Select value={newMemberRole} onValueChange={setNewMemberRole}>
                    <SelectTrigger>
                        <SelectValue placeholder="Select a role" />
                    </SelectTrigger>
                    <SelectContent>
                        <SelectItem value="member">Member</SelectItem>
                        <SelectItem value="admin">Admin</SelectItem>
                        <SelectItem value="owner">Owner</SelectItem>
                    </SelectContent>
                    </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button type="submit" disabled={addMemberMutation.isPending}>
                {addMemberMutation.isPending ? 'Adding...' : 'Add Member'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={isDeleteConfirmOpen} onOpenChange={setIsDeleteConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Team</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this team? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsDeleteConfirmOpen(false)}>Cancel</Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={deleteTeamMutation.isPending}>
              {deleteTeamMutation.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
