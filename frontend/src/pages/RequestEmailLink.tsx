import { useMutation } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Link } from 'react-router-dom'
import { getErrorMessage } from "@/lib/utils"

interface RequestEmailLinkProps {
  title: string
  description: string
  submitLabel: string
  requestLink: (email: string) => Promise<{ message: string }>
}

export default function RequestEmailLink({ title, description, submitLabel, requestLink }: Readonly<RequestEmailLinkProps>) {
  const { mutate, isPending, data, error } = useMutation({ mutationFn: requestLink })

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    mutate(new FormData(event.currentTarget).get('email') as string)
  }

  return (
    <div className="flex h-screen items-center justify-center bg-muted/50">
      <Card className="w-[350px]">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-2">
            <img src="/logo.png" alt="Logo" className="h-12 w-auto object-contain" />
          </div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>
            {description}
          </CardDescription>
        </CardHeader>
        <form onSubmit={onSubmit}>
          <CardContent>
            <div className="grid w-full items-center gap-4">
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor="email">Email</Label>
                <Input id="email" name="email" type="email" required />
              </div>
              {data && (
                <div className="text-sm text-success">
                  {data.message}
                </div>
              )}
              {error && (
                <div className="text-sm text-destructive">
                  {getErrorMessage(error)}
                </div>
              )}
            </div>
          </CardContent>
          <CardFooter className="flex flex-col gap-2">
            <Button type="submit" className="w-full" disabled={isPending}>
              {isPending ? "Sending..." : submitLabel}
            </Button>
            <div className="text-sm text-center text-muted-foreground">
              <Link to="/login" className="text-primary hover:underline">Back to Login</Link>
            </div>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}
