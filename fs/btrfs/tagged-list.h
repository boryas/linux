#ifndef TAGGED_LIST_H_
#define TAGGED_LIST_H_

#include <linux/list.h>

struct tagged_list_head {
	struct list_head *head;
	struct list_head l;
};

static inline void INIT_TAGGED_LIST_HEAD(struct tagged_list_head *tl)
{
	tl->head = NULL;
	INIT_LIST_HEAD(&tl->l);
}

// add: invalid if already on a list
void tagged_list_head_add(struct tagged_list_head *tl, struct list_head *head);
void tagged_list_head_add_tail(struct tagged_list_head *tl, struct list_head *head);
// move: invalid if not yet on a list
void tagged_list_head_move(struct tagged_list_head *tl, struct list_head *head);
void tagged_list_head_move_tail(struct tagged_list_head *tl, struct list_head *head);
// link: handle either case
void tagged_list_head_link(struct tagged_list_head *tl, struct list_head *head);
void tagged_list_head_link_tail(struct tagged_list_head *tl, struct list_head *head);
// del: ok if on list
void tagged_list_head_del(struct tagged_list_head *tl);
void tagged_list_head_del_init(struct tagged_list_head *tl);

#endif // TAGGED_LIST_H_
