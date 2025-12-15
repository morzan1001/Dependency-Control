import { useState, useEffect } from 'react';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { getTeams, Team } from '@/lib/api';
import { useAuth } from '@/context/AuthContext';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { CreateTeamDialog } from '@/components/teams/CreateTeamDialog';
import { TeamCard } from '@/components/teams/TeamCard';
import { EditTeamDialog } from '@/components/teams/EditTeamDialog';
import { TeamMembersDialog } from '@/components/teams/TeamMembersDialog';
import { AddMemberDialog } from '@/components/teams/AddMemberDialog';
import { DeleteTeamDialog } from '@/components/teams/DeleteTeamDialog';

export default function TeamsPage() {
  const { hasPermission } = useAuth();
  
  // Dialog States
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isManageMembersOpen, setIsManageMembersOpen] = useState(false);
  const [isAddMemberOpen, setIsAddMemberOpen] = useState(false);
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  
  // Selection States
  const [selectedTeam, setSelectedTeam] = useState<Team | null>(null);
  const [selectedTeamIdForAddMember, setSelectedTeamIdForAddMember] = useState<string | null>(null);
  const [teamToDelete, setTeamToDelete] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  const { data: teams, isLoading, error } = useQuery({
    queryKey: ['teams', debouncedSearch],
    queryFn: () => getTeams(debouncedSearch),
    placeholderData: keepPreviousData,
  });

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
    return <div className="text-red-500">Error loading teams</div>;
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
