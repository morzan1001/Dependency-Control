import { Team } from '@/types/team';
import { useAuth } from '@/context/useAuth';
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { UserPlus, Trash2, Edit } from 'lucide-react';

interface TeamCardProps {
  team: Team;
  onEdit: (team: Team) => void;
  onManageMembers: (team: Team) => void;
  onAddMember: (teamId: string) => void;
  onDelete: (teamId: string) => void;
}

export function TeamCard({ team, onEdit, onManageMembers, onAddMember, onDelete }: TeamCardProps) {
  const { hasPermission } = useAuth();

  return (
    <Card 
      className="flex flex-col cursor-pointer hover:bg-muted/50 transition-colors"
      onClick={() => onManageMembers(team)}
    >
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">
          {team.name}
        </CardTitle>
        <div className="flex items-center gap-1">
            {hasPermission('team:update') && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                onClick={(e: React.MouseEvent) => {
                  e.stopPropagation();
                  onEdit(team);
                }}
              >
                  <Edit className="h-4 w-4" />
              </Button>
            )}
            {hasPermission('team:delete') && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-destructive hover:text-destructive/90"
                onClick={(e: React.MouseEvent) => {
                  e.stopPropagation();
                  onDelete(team._id);
                }}
              >
                  <Trash2 className="h-4 w-4" />
              </Button>
            )}
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
          {hasPermission('team:update') && (
            <Button 
              variant="outline" 
              className="w-full" 
              onClick={(e: React.MouseEvent) => {
                e.stopPropagation();
                onAddMember(team._id);
              }}
            >
                <UserPlus className="mr-2 h-4 w-4" />
                Add Member
            </Button>
          )}
      </CardFooter>
    </Card>
  );
}
