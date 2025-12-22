#include "messages.h"
#include "tagged-list.h"

LIST_HEAD(dirty);
LIST_HEAD(switch_commits);

void tagged_list_add(struct tagged_list_head *tl, struct list_head *head)
{
	ASSERT(tl->head == NULL);
	list_add(&tl->l, head);
	tl->head = head;
}

void tagged_list_add_tail(struct tagged_list_head *tl, struct list_head *head)
{
	ASSERT(tl->head == NULL);
	list_add_tail(&tl->l, head);
	tl->head = head;
}

void tagged_list_move(struct tagged_list_head *tl, struct list_head *head)
{
	ASSERT(tl->head != NULL);
	// ?
	ASSERT(tl->head != head);

	list_move(&tl->l, head);
	tl->head = head;
}

void tagged_list_move_tail(struct tagged_list_head *tl, struct list_head *head)
{
	ASSERT(tl->head != NULL);
	// ?
	ASSERT(tl->head != head);

	list_move_tail(&tl->l, head);
	tl->head = head;
}

void tagged_list_link(struct tagged_list_head *tl, struct list_head *head)
{
	if (tl->head == NULL)
		tagged_list_add(tl, head);
	else
		tagged_list_move(tl, head);
}

void tagged_list_link_tail(struct tagged_list_head *tl, struct list_head *head)
{
	if (tl->head == NULL)
		tagged_list_add_tail(tl, head);
	else
		tagged_list_move_tail(tl, head);
}

void tagged_list_del(struct tagged_list_head *tl)
{
	tl->head = NULL;
	list_del(&tl->l);
}

void tagged_list_del_init(struct tagged_list_head *tl)
{
	tl->head = NULL;
	list_del_init(&tl->l);
}
