import { useState } from 'react';
import { useTeams } from '@/hooks/queries/use-teams';
import { Team } from '@/types/team';
import { useAuth } from '@/context/useAuth';
import { useDebounce } from '@/hooks/use-debounce';
import { DEBOUNCE_DELAY_MS } from '@/lib/constants';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { CreateTeamDialog } from '@/components/teams/CreateTeamDialog';
import { TeamCard } from '@/components/teams/TeamCard';
import { EditTeamDialog } from '@/components/teams/EditTeamDialog';
import { TeamMembersDialog } from '@/components/teams/TeamMembersDialog';
import { AddMemberDialog } from '@/components/teams/AddMemberDialog';
import { DeleteTeamDialog } from '@/components/teams/DeleteTeamDialog';
import { ArrowUp, ArrowDown } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export default function TeamsPage() {
  const { hasPermission } = useAuth();
  
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isManageMembersOpen, setIsManageMembersOpen] = useState(false);
  const [isAddMemberOpen, setIsAddMemberOpen] = useState(false);
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const [selectedTeam, setSelectedTeam] = useState<Team | null>(null);
  const [selectedTeamIdForAddMember, setSelectedTeamIdForAddMember] = useState<string | null>(null);
  const [teamToDelete, setTeamToDelete] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState("name");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");

  const debouncedSearch = useDebounce(search, DEBOUNCE_DELAY_MS);

  const { data: teams, isLoading, error } = useTeams(debouncedSearch, sortBy, sortOrder);

  const openEditDialog = (team: Team) => {
    setSelectedTeam(team);
    setIsEditOpen(true);
  };

  const openManageMembersDialog = (team: Team) => {
    setSelectedTeam(team);
    setIsManageMembersOpen(true);
  };

  const openAddMemberDialog = (teamId: string) => {
    setSelectedTeamIdForAddMember(teamId);
    setIsAddMemberOpen(true);
  };

  const handleDeleteClick = (teamId: string) => {
      setTeamToDelete(teamId);
      setIsDeleteConfirmOpen(true);
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-10 w-32" />
        </div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
          <Skeleton className="h-48 rounded-xl" />
        </div>
      </div>
    );
  }

  if (error) {
    return <div className="text-destructive">Error loading teams</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold tracking-tight">Teams</h1>
        <div className="flex items-center gap-2">
          <Input 
            placeholder="Search teams..." 
            value={search} 
            onChange={(e) => setSearch(e.target.value)}
            className="w-[250px]"
          />
          <Select value={sortBy} onValueChange={setSortBy}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="name">Name</SelectItem>
              <SelectItem value="created_at">Created Date</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="icon"
            onClick={() => setSortOrder(sortOrder === "asc" ? "desc" : "asc")}
          >
            {sortOrder === "asc" ? <ArrowUp className="h-4 w-4" /> : <ArrowDown className="h-4 w-4" />}
          </Button>
          {hasPermission('team:create') && <CreateTeamDialog />}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {teams?.map((team: Team) => (
          <TeamCard 
            key={team._id} 
            team={team}
            onEdit={openEditDialog}
            onManageMembers={openManageMembersDialog}
            onAddMember={openAddMemberDialog}
            onDelete={handleDeleteClick}
          />
        ))}
      </div>

      <EditTeamDialog 
        key={selectedTeam?._id}
        team={selectedTeam} 
        isOpen={isEditOpen} 
        onClose={() => setIsEditOpen(false)} 
      />

      <TeamMembersDialog 
        team={selectedTeam} 
        isOpen={isManageMembersOpen} 
        onClose={() => setIsManageMembersOpen(false)} 
      />

      <AddMemberDialog 
        teamId={selectedTeamIdForAddMember} 
        isOpen={isAddMemberOpen} 
        onClose={() => setIsAddMemberOpen(false)} 
      />

      <DeleteTeamDialog 
        teamId={teamToDelete} 
        isOpen={isDeleteConfirmOpen} 
        onClose={() => setIsDeleteConfirmOpen(false)} 
      />
    </div>
  );
}
